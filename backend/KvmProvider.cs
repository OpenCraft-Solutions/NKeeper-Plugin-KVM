using System.Globalization;
using System.Text.RegularExpressions;
using NKeeper.Abstractions;
using NKeeper.Plugins.Virtualization;

namespace NKeeper.Plugins.Kvm;

/// <summary>
/// KVM hypervisors for virt-core (docs/architecture.md §7.37), the way virt-manager reaches them, ported from 1.x's
/// <c>KvmHost</c>: over SSH, which core opens and signs in to (§7.9), running <c>virsh</c> against <c>qemu:///system</c>.
/// </summary>
public sealed class KvmProvider(IConnectivity connectivity) : IGuestProvider
{
    public const string PluginId = "kvm";

    string IGuestProvider.PluginId => PluginId;

    public string Product => "KVM";

    public async Task<IGuestConnection> OpenAsync(StreamSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var handle = request.Credential ?? throw new ConnectException(ConnectFailure.NoSecret, "Choose a credential, or type one, to sign in to the hypervisor.");
        return new KvmConnection(await connectivity.OpenSshAsync(request.Host, request.ServiceId, handle, cancellationToken));
    }
}

/// <summary>One SSH connection to a KVM hypervisor: its guests, their power, and their consoles through SSH port forwards (SDK 1.11).</summary>
public sealed partial class KvmConnection(ISshConnection ssh) : IGuestConnection
{
    private const string Virsh = "virsh -c qemu:///system";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(30);

    /// <summary>All guests (running or not), with their state and graphical display, in one round trip, tab-separated.</summary>
    internal const string ListScript =
        "c='" + Virsh + "'; uuids=$($c list --all --uuid) || exit 3; for u in $uuids; do "
        + "printf '%s\\t%s\\t%s\\t%s\\n' \"$u\" \"$($c domname \"$u\")\" \"$($c domstate \"$u\")\" \"$($c domdisplay \"$u\" 2>/dev/null | head -n 1)\"; done";

    public async Task<IReadOnlyList<Guest>> ListAsync(CancellationToken cancellationToken) =>
        ParseListing(await RunAsync(ListScript, CommandTimeout, cancellationToken));

    public Task PowerAsync(string guestId, string action, CancellationToken cancellationToken) =>
        // The UUID is formatted by us (never user text) and the command is one of ours, so both are safe in the command line.
        RunAsync($"{Virsh} {Command(action)} {Uuid(guestId):D}", TimeSpan.FromMinutes(10), cancellationToken);

    public async Task<GuestConsole> OpenConsoleAsync(string guestId, CancellationToken cancellationToken)
    {
        var id = Uuid(guestId);
        var output = await RunAsync(
            $"{Virsh} domdisplay --include-password {id:D} 2>/dev/null || {Virsh} domdisplay {id:D}",
            CommandTimeout,
            cancellationToken);
        var display = ParseDisplayUri(output.Trim().Split('\n')[0].Trim())
            ?? throw new GuestException("This guest has no graphical display, or it isn't running.");
        if (display.Protocol != ConsoleProtocols.Vnc)
        {
            throw new GuestException("This guest's console is SPICE, which the browser can't show yet. Give it a VNC display (it can listen on localhost only).");
        }

        // The display listens on the hypervisor, usually on its loopback: reached through the SSH connection (SDK 1.11).
        var forwarded = await ssh.ForwardAsync(display.Host, display.Port, cancellationToken);
        return new GuestConsole(display.Protocol, display.Password, forwarded.Stream, () => forwarded.DisposeAsync());
    }

    public ValueTask DisposeAsync() => ssh.DisposeAsync();

    /// <summary>virsh's listing as guests, by name, with the power actions each state takes.</summary>
    internal static IReadOnlyList<Guest> ParseListing(string output)
    {
        var guests = new List<Guest>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var fields = line.Split('\t');
            if (fields.Length >= 3 && Guid.TryParse(fields[0], out var uuid))
            {
                var scheme = fields.ElementAtOrDefault(3) is { Length: > 0 } uri ? uri.Split(':', 2)[0].ToLowerInvariant() : null;
                var console = scheme is ConsoleProtocols.Spice or ConsoleProtocols.Vnc ? scheme : null;
                guests.Add(new Guest(uuid.ToString("D"), fields[1], fields[2], console, Actions(fields[2])));
            }
        }

        return [.. guests.OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>The power actions a guest takes in a state (virsh's words for it).</summary>
    internal static IReadOnlyList<string> Actions(string state) => state switch
    {
        "running" or "idle" => [GuestActions.Shutdown, GuestActions.Reboot, GuestActions.Pause, GuestActions.Hibernate, GuestActions.Stop, GuestActions.Reset],
        "paused" => [GuestActions.Resume, GuestActions.Stop],
        "shut off" or "crashed" => [GuestActions.Start],
        "pmsuspended" => [GuestActions.Start, GuestActions.Stop],
        _ => [GuestActions.Stop],
    };

    /// <summary>
    /// The virsh command for an action. Hibernating is a managed save (memory to disk, then off); starting a guest with
    /// one resumes it. Stopping is <c>destroy</c>: off at once, nothing deleted.
    /// </summary>
    internal static string Command(string action) => action switch
    {
        GuestActions.Start or GuestActions.Shutdown or GuestActions.Reboot or GuestActions.Resume or GuestActions.Reset => action,
        GuestActions.Pause => "suspend",
        GuestActions.Hibernate => "managedsave",
        GuestActions.Stop => "destroy",
        _ => throw new GuestException($"“{action}” isn't a power action KVM has."),
    };

    private static Guid Uuid(string guestId) =>
        Guid.TryParse(guestId, out var id) ? id : throw new GuestException("That isn't a KVM guest's ID.");

    /// <summary>Where a guest's console listens on the hypervisor, and its password if libvirt gives it.</summary>
    internal sealed record Display(string Protocol, string Host, int Port, string? Password);

    /// <summary>
    /// Parses libvirt's display URI, e.g. <c>spice://127.0.0.1:5900</c>, <c>spice://127.0.0.1:5900/?password=secret</c>
    /// or <c>vnc://127.0.0.1:0</c>. For VNC, virsh prints the display number (port 5900 + N), not the port. A display on
    /// every address is reached on the hypervisor's loopback. TLS-only SPICE ports aren't supported.
    /// </summary>
    internal static Display? ParseDisplayUri(string text)
    {
        var match = DisplayUri().Match(text);
        if (!match.Success)
        {
            return null;
        }

        var protocol = match.Groups["scheme"].Value.ToLowerInvariant();
        var host = match.Groups["host"].Value.Trim('[', ']');
        var query = match.Groups["query"].Value;
        var password = match.Groups["userPassword"].Success ? match.Groups["userPassword"].Value : QueryValue(query, "password");
        if (!match.Groups["port"].Success)
        {
            throw new GuestException(
                protocol == ConsoleProtocols.Spice && QueryValue(query, "tls-port") is not null
                    ? "This guest's SPICE display only accepts TLS connections, which the browser console doesn't support. Add a plain port (it can listen on localhost only)."
                    : $"Couldn't read the guest's {protocol.ToUpperInvariant()} address.");
        }

        var port = int.Parse(match.Groups["port"].Value, CultureInfo.InvariantCulture);
        if (protocol == ConsoleProtocols.Vnc)
        {
            port += 5900;
        }

        if (port > 65535)
        {
            throw new GuestException($"Couldn't read the guest's {protocol.ToUpperInvariant()} address.");
        }

        if (host is "" or "0.0.0.0" or "::")
        {
            host = "127.0.0.1";
        }

        return new Display(protocol, host, port, string.IsNullOrEmpty(password) ? null : Uri.UnescapeDataString(password));
    }

    private static string? QueryValue(string query, string name) =>
        query.TrimStart('?').Split('&').Select(p => p.Split('=', 2)).FirstOrDefault(p => p[0] == name && p.Length == 2)?[1];

    /// <summary>Runs a command and returns its output, or explains why libvirt refused.</summary>
    private async Task<string> RunAsync(string command, TimeSpan timeout, CancellationToken cancellationToken)
    {
        SshCommandResult result;
        try
        {
            result = await ssh.RunAsync(command, timeout, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new GuestException("The hypervisor didn't answer in time.");
        }

        if (result.ExitStatus is not 0)
        {
            var error = result.Error.Trim();
            throw new GuestException(
                result.ExitStatus == 127 || error.Contains("not found", StringComparison.OrdinalIgnoreCase)
                    ? "virsh isn't installed on this host. Install the libvirt client tools (e.g. libvirt-clients or libvirt-client)."
                    : $"libvirt refused the request: {(error.Length > 0 ? error.Split('\n')[0] : $"exit code {result.ExitStatus}")}. The SSH user needs access to qemu:///system (e.g. membership in the libvirt group).");
        }

        return result.Output;
    }

    [GeneratedRegex(@"^(?<scheme>spice|vnc)://(?::(?<userPassword>[^@]*)@)?(?<host>\[[^\]]+\]|[^:/?]*)(?::(?<port>\d{1,5}))?/?(?<query>\?.*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex DisplayUri();
}
