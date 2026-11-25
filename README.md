# NKeeper KVM plugin

The official `kvm` plugin for [NKeeper](https://github.com/OpenCraft-Solutions/NKeeper) 2.0: KVM hypervisors' virtual machines, ported from 1.x's KVM support. It lives in a repository of its own and is released on its own (NKeeper's `docs/architecture.md` §9). Its design is §7.37 there.

## What it does

It contributes the `kvm` service type (SSH, port 22) and a **Virtual machines** tab for hosts that have it. The tab is virt-core's guests tab (§7.36), which this plugin depends on:
- the hypervisor's guests (running or not), with their state;
- their power actions: start, shut down, reboot, pause, resume, hibernate (a managed save), force off and reset;
- a guest's VNC console in the same tab.

It reaches the hypervisor as virt-manager does: over SSH, which core opens and signs in to with the service's credential, running `virsh -c qemu:///system`. The SSH user needs access to libvirt's system connection (membership in the `libvirt` group, usually). A guest's VNC display, usually on the hypervisor's loopback, is reached through an SSH port forward, so it never needs to listen on the network. It needs SDK 1.15 (`>=1.15.0 <2.0.0`): port forwards since 1.11, and scan findings with guests.

**Scan** (host action `kvm.scan`, SDK 1.15), 1.x's hypervisor scan: one SSH login lists every guest with `virsh`, with its state, vCPUs, memory, MAC addresses (`domiflist`) and the addresses libvirt knows (the guest agent's, else its DHCP leases). The scan dialog proposes linking each guest to the host it is, as running on this hypervisor, or adding a host for it (NKeeper's `docs/architecture.md` §7.49). Nothing on the hypervisor changes; the scan is audited as `kvm.scan`.

**Not yet:** SPICE consoles (a guest with only SPICE is explained, not shown), and TLS-only displays.

The plugin's ID is `kvm`, and it is built in: it is signed with NKeeper's official key and installed with NKeeper.

## Layout

```text
backend/        the provider (KvmProvider.cs), the plugin, nkeeper-plugin.json (the manifest), the project
frontend/       the session view: virt-core's guests tab, told it's KVM
tests/          the provider's tests, on a stand-in for core's SSH connection and libvirt's output
.github/        CI and the release workflow
```

It builds against NKeeper's published SDK and virt-core's package, never core's source: `NKeeper.Abstractions`, `NKeeper.Plugin.Build` and `NKeeper.Plugins.Virtualization` (NuGet), and `@opencraft-solutions/nkeeper-sdk` (npm, imported as `@nkeeper/sdk`), all from GitHub Packages.

## Building

You need the .NET 10 SDK (see `global.json`) and Node.js 24 (see `.nvmrc`). GitHub Packages needs a token even for public packages; give the build one that can read packages, in the environment, never in the repository:

```bash
export NUGET_USERNAME=<your GitHub user name>
export NUGET_AUTH_TOKEN=<token>
export NODE_AUTH_TOKEN=<token>
(cd frontend && npm ci && npm run lint && npm run typecheck)
dotnet build NKeeper.Plugins.Kvm.slnx --configuration Release
dotnet test NKeeper.Plugins.Kvm.slnx --configuration Release
```

The build packs `kvm-<version>.nkp` into `artifacts/plugins/`, signed with a development key it creates under `.dev/keys/`. Load it in a development NKeeper beside virt-core's package.

## Releasing

Raise `version` in `backend/nkeeper-plugin.json` (and `frontend/package.json`), merge to `main`, and push a tag `v<version>`. The release workflow builds and tests, then, in the protected `release` environment that needs an owner's approval, packs the package signed with the official key and publishes a GitHub release with it and its SHA-256.

## License

MIT, as NKeeper. See [LICENSE](LICENSE).
