using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NKeeper.Abstractions;
using NKeeper.Plugins.Virtualization;

namespace NKeeper.Plugins.Kvm;

/// <summary>
/// The kvm plugin (docs/architecture.md §7.37): the <c>kvm</c> service type and its guests tab, which virt-core runs and
/// draws (§7.36). Core opens the SSH connection and signs in (§7.9); this plugin never sees the password.
/// </summary>
public sealed class KvmPlugin : IPlugin
{
    public const string ServiceType = "kvm";

    public const string SessionType = "kvm";

    public void Contribute(IPluginContributions contributions, PluginContext context)
    {
        contributions.AddServiceType(new ServiceType(ServiceType, "KVM") { DefaultPort = 22, Health = HealthProbe.Tcp });
        contributions.AddSessionType(new SessionType(SessionType, "Virtual machines", typeof(GuestSessionHandler<KvmProvider>)) { ServiceTypes = [ServiceType] });
        contributions.AddHostAction(new HostAction("kvm.guests", "Virtual machines", SessionType: SessionType));
    }

    public void ConfigureServices(IServiceCollection services, PluginContext context) => services.AddGuestProvider<KvmProvider>();

    public void MapEndpoints(IEndpointRouteBuilder endpoints, PluginContext context)
    {
    }
}
