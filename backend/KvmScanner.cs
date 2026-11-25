using System.Globalization;
using Microsoft.AspNetCore.Http;
using NKeeper.Abstractions;

namespace NKeeper.Plugins.Kvm;

/// <summary>What the shell posts to a scan action (docs/architecture.md §7.26).</summary>
internal sealed record ScanRequest(Guid ServiceId, Guid? CredentialId, string? PromptReference);

/// <summary>
/// 1.x's hypervisor scan (docs/architecture.md §7.37, §7.49), on SDK 1.15: the hypervisor's guests, each with its state,
/// vCPUs, memory, MAC addresses and the addresses libvirt knows, over one SSH login, which core opens and signs in to.
/// The shell proposes linking each to the host it is. Nothing on the hypervisor changes.
/// </summary>
internal static class KvmScanner
{
    private const string Virsh = "virsh -c qemu:///system";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    /// <summary>One line per guest, tab-separated: UUID, name, state, vCPUs, memory (KiB), MACs and addresses (comma-separated).</summary>
    internal const string Script =
        "c='" + Virsh + "'; uuids=$($c list --all --uuid) || exit 3; for u in $uuids; do "
        + "info=$($c dominfo \"$u\" 2>/dev/null); "
        + "cpus=$(printf '%s\\n' \"$info\" | sed -n 's/^CPU(s):[[:space:]]*//p'); "
        + "mem=$(printf '%s\\n' \"$info\" | sed -n 's/^Max memory:[[:space:]]*\\([0-9]*\\).*/\\1/p'); "
        + "macs=$($c domiflist \"$u\" 2>/dev/null | awk 'NR>2 && $5 ~ /:/ {print $5}' | paste -sd, -); "
        + "ips=$( { $c domifaddr \"$u\" --source agent 2>/dev/null || $c domifaddr \"$u\" 2>/dev/null; } | awk 'NR>2 && $4 ~ /\\// {split($4,a,\"/\"); print a[1]}' | paste -sd, -); "
        + "printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$u\" \"$($c domname \"$u\")\" \"$($c domstate \"$u\")\" \"$cpus\" \"$mem\" \"$macs\" \"$ips\"; done";

    internal static async Task<IResult> ScanAsync(HostContext host, ScanRequest request, ICredentialBroker broker, IConnectivity connectivity, IPluginAudit audit, CancellationToken cancellationToken)
    {
        if (host.Services.FirstOrDefault(s => s.Id == request.ServiceId) is not { Type: KvmPlugin.ServiceType })
        {
            return Problem(StatusCodes.Status400BadRequest, "bad_request", "This host has no such KVM service. Reload the host and try again.");
        }

        try
        {
            var handle = request.CredentialId is { } credentialId
                ? await broker.ResolveSavedAsync(host, request.ServiceId, credentialId, cancellationToken)
                : request.PromptReference is { Length: > 0 } reference
                    ? await broker.ResolvePromptAsync(host, request.ServiceId, reference, cancellationToken)
                    : throw new ConnectException(ConnectFailure.NoSecret, "Choose a credential, or type one, to scan the hypervisor.");
            await using var ssh = await connectivity.OpenSshAsync(host, request.ServiceId, handle, cancellationToken);
            SshCommandResult result;
            try
            {
                result = await ssh.RunAsync(Script, Timeout, cancellationToken);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Problem(StatusCodes.Status504GatewayTimeout, "timeout", "The hypervisor didn't finish the scan in time.");
            }

            if (result.ExitStatus is not 0)
            {
                var error = result.Error.Trim();
                return Problem(
                    StatusCodes.Status409Conflict,
                    "libvirt_refused",
                    result.ExitStatus == 127 || error.Contains("not found", StringComparison.OrdinalIgnoreCase)
                        ? "virsh isn't installed on this host. Install the libvirt client tools (e.g. libvirt-clients or libvirt-client)."
                        : $"libvirt refused the scan: {(error.Length > 0 ? error.Split('\n')[0] : $"exit code {result.ExitStatus}")}. The SSH user needs access to qemu:///system (e.g. membership in the libvirt group).");
            }

            var guests = Parse(result.Output);
            var findings = new ScanFindings
            {
                Guests = guests,
                Notes = [$"libvirt runs {guests.Count} {(guests.Count == 1 ? "guest" : "guests")}. Addresses come from the guest agent, or else the DHCP leases libvirt gave out."],
            };
            await audit.RecordAsync("kvm.scan", host.Id, $"service {request.ServiceId}: {guests.Count} guests", cancellationToken);
            return Results.Ok(findings);
        }
        catch (ConnectException ex)
        {
            return ex.Presented is { } presented
                ? Problem(StatusCodes.Status409Conflict, "host_key_unknown", ex.Message, presented)
                : Problem(ex.Reason == ConnectFailure.NoSecret ? StatusCodes.Status400BadRequest : StatusCodes.Status502BadGateway, Code(ex.Reason), ex.Message);
        }
        catch (CredentialDeniedException ex)
        {
            return Problem(StatusCodes.Status403Forbidden, "credential_denied", ex.Message);
        }
    }

    /// <summary>The script's lines as guests; a line that isn't one is skipped.</summary>
    internal static IReadOnlyList<ScannedGuest> Parse(string output)
    {
        var guests = new List<ScannedGuest>();
        // Only the line ending is trimmed: a guest without addresses ends in an empty field.
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.TrimEnd('\r').Split('\t');
            if (fields.Length < 7 || !Guid.TryParse(fields[0], out _) || fields[1].Length == 0)
            {
                continue;
            }

            static IReadOnlyList<string> List(string text) => [.. text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase)];
            guests.Add(new ScannedGuest(
                fields[1],
                fields[2].Length == 0 ? null : fields[2],
                List(fields[5]),
                [.. List(fields[6]).Where(a => System.Net.IPAddress.TryParse(a, out var ip) && !System.Net.IPAddress.IsLoopback(ip))],
                int.TryParse(fields[3], NumberStyles.None, CultureInfo.InvariantCulture, out var cpus) && cpus > 0 ? cpus : null,
                long.TryParse(fields[4], NumberStyles.None, CultureInfo.InvariantCulture, out var kib) && kib >= 1024 ? (int)Math.Min(kib / 1024, int.MaxValue) : null));
        }

        return guests;
    }

    private static IResult Problem(int status, string code, string detail, PresentedIdentity? presented = null)
    {
        var extensions = new Dictionary<string, object?> { ["code"] = code };
        if (presented is not null)
        {
            extensions["presented"] = presented;
        }

        return Results.Problem(statusCode: status, detail: detail, extensions: extensions);
    }

    private static string Code(ConnectFailure reason) => reason switch
    {
        ConnectFailure.HostKeyChanged => "host_key_changed",
        ConnectFailure.AuthenticationFailed => "authentication_failed",
        ConnectFailure.NoSecret => "no_secret",
        ConnectFailure.InvalidPrivateKey => "invalid_private_key",
        ConnectFailure.TimedOut => "timeout",
        ConnectFailure.JumpHostUnavailable => "jump_host_unavailable",
        _ => "unreachable",
    };
}
