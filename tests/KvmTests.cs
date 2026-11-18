using System.Text;
using NKeeper.Abstractions;
using NKeeper.Plugins.Virtualization;

namespace NKeeper.Plugins.Kvm.Tests;

/// <summary>The KVM provider (docs/architecture.md §7.37) on a stand-in for core's SSH connection, and libvirt's output, from 1.x's tests.</summary>
public sealed class KvmTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Web = "5b3a2c9e-1f4d-4e8a-9c0b-7d6e5f4a3b21";
    private const string Db = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    [Fact]
    public async Task Guests_are_listed_by_name_with_their_consoles_and_actions()
    {
        var ssh = new FakeSsh { Output = $"{Web}\tweb01\trunning\tspice://127.0.0.1:5900\n{Db}\tdb01\tshut off\t\nnot-a-uuid\tjunk\trunning\t\n" };
        await using var connection = new KvmConnection(ssh);

        var guests = await connection.ListAsync(Ct);

        Assert.Equal(["db01", "web01"], guests.Select(g => g.Name));
        Assert.Null(guests[0].Console);
        Assert.Equal([GuestActions.Start], guests[0].Actions);
        Assert.Equal("spice", guests[1].Console);
        Assert.Contains(GuestActions.Reset, guests[1].Actions);
        Assert.Equal(KvmConnection.ListScript, Assert.Single(ssh.Commands));
    }

    [Theory]
    [InlineData("start", "start")]
    [InlineData("shutdown", "shutdown")]
    [InlineData("reboot", "reboot")]
    [InlineData("pause", "suspend")]
    [InlineData("hibernate", "managedsave")]
    [InlineData("resume", "resume")]
    [InlineData("stop", "destroy")]
    [InlineData("reset", "reset")]
    public async Task Each_power_action_is_its_virsh_command(string action, string command)
    {
        var ssh = new FakeSsh();
        await using var connection = new KvmConnection(ssh);

        await connection.PowerAsync(Web, action, Ct);

        Assert.Equal($"virsh -c qemu:///system {command} {Web}", Assert.Single(ssh.Commands));
    }

    [Fact]
    public async Task A_guest_ID_that_isnt_a_UUID_never_reaches_the_command_line_and_libvirts_refusal_is_explained()
    {
        var ssh = new FakeSsh();
        await using var connection = new KvmConnection(ssh);
        Assert.Contains("isn't a KVM guest", (await Assert.ThrowsAsync<GuestException>(() => connection.PowerAsync("x; rm -rf /", "start", Ct))).Message, StringComparison.Ordinal);
        Assert.Empty(ssh.Commands);

        ssh.Result = new SshCommandResult(1, string.Empty, "error: Failed to connect socket: Permission denied\n");
        Assert.Contains("libvirt group", (await Assert.ThrowsAsync<GuestException>(() => connection.PowerAsync(Web, "start", Ct))).Message, StringComparison.Ordinal);
        ssh.Result = new SshCommandResult(127, string.Empty, "sh: virsh: not found");
        Assert.Contains("isn't installed", (await Assert.ThrowsAsync<GuestException>(() => connection.ListAsync(Ct))).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_VNC_console_is_forwarded_from_the_hypervisors_loopback_with_its_password()
    {
        var ssh = new FakeSsh { Output = "vnc://:s3cret@0.0.0.0:1\n" };
        await using var connection = new KvmConnection(ssh);

        await using var console = await connection.OpenConsoleAsync(Web, Ct);

        Assert.Equal(("vnc", "s3cret"), (console.Protocol, console.Password));
        Assert.Equal(("127.0.0.1", 5901), Assert.Single(ssh.Forwards));
        Assert.Contains($"domdisplay --include-password {Web}", ssh.Commands[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_SPICE_console_or_none_is_explained()
    {
        await using var spice = new KvmConnection(new FakeSsh { Output = "spice://127.0.0.1:5900\n" });
        Assert.Contains("SPICE", (await Assert.ThrowsAsync<GuestException>(() => spice.OpenConsoleAsync(Web, Ct))).Message, StringComparison.Ordinal);

        await using var none = new KvmConnection(new FakeSsh { Output = "\n" });
        Assert.Contains("no graphical display", (await Assert.ThrowsAsync<GuestException>(() => none.OpenConsoleAsync(Web, Ct))).Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("spice://127.0.0.1:5900", "127.0.0.1", 5900, null)]
    [InlineData("spice://127.0.0.1:5901/?password=s3cret", "127.0.0.1", 5901, "s3cret")]
    [InlineData("spice://:p%40ss@localhost:5902", "localhost", 5902, "p@ss")]
    [InlineData("spice://0.0.0.0:5903", "127.0.0.1", 5903, null)]
    [InlineData("spice://[::1]:5904", "::1", 5904, null)]
    public void Spice_URIs_are_parsed(string uri, string host, int port, string? password) =>
        Assert.Equal(new KvmConnection.Display("spice", host, port, password), KvmConnection.ParseDisplayUri(uri));

    [Theory]
    [InlineData("vnc://127.0.0.1:0", "127.0.0.1", 5900, null)]
    [InlineData("vnc://:s3cret@127.0.0.1:1", "127.0.0.1", 5901, "s3cret")]
    [InlineData("vnc://0.0.0.0:12", "127.0.0.1", 5912, null)]
    [InlineData("VNC://[::1]:3", "::1", 5903, null)]
    public void VNC_URIs_are_parsed_with_display_numbers_as_ports(string uri, string host, int port, string? password) =>
        Assert.Equal(new KvmConnection.Display("vnc", host, port, password), KvmConnection.ParseDisplayUri(uri));

    [Fact]
    public void A_TLS_only_SPICE_display_is_explained() =>
        Assert.Contains("TLS", Assert.Throws<GuestException>(() => KvmConnection.ParseDisplayUri("spice://127.0.0.1?tls-port=5901")).Message, StringComparison.Ordinal);
}

/// <summary>Core's SSH connection, as the provider sees it: commands answered from <see cref="Output"/>, forwards to a stream.</summary>
internal sealed class FakeSsh : ISshConnection
{
    public string Output { get; set; } = string.Empty;

    public SshCommandResult? Result { get; set; }

    public List<string> Commands { get; } = [];

    public List<(string Address, int Port)> Forwards { get; } = [];

    public Task<SshCommandResult> RunAsync(string command, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        Commands.Add(command);
        return Task.FromResult(Result ?? new SshCommandResult(0, Output, string.Empty));
    }

    public Task<ISshShell> OpenShellAsync(SshTerminal terminal, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<ITcpConnection> ForwardAsync(string address, int port, CancellationToken cancellationToken = default)
    {
        Forwards.Add((address, port));
        return Task.FromResult<ITcpConnection>(new Tcp(address, port));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private sealed class Tcp(string address, int port) : ITcpConnection
    {
        public Stream Stream { get; } = new MemoryStream(Encoding.ASCII.GetBytes("RFB 003.008\n"));

        public string Address => address;

        public int Port => port;

        public ValueTask DisposeAsync() => Stream.DisposeAsync();
    }
}
