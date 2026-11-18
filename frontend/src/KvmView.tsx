import type { SessionViewProps } from '@nkeeper/sdk'
import { virtCore, type HypervisorInfo } from './virtCore'

const KVM: HypervisorInfo = { product: 'KVM' }

/** The KVM tab: virt-core's guests tab, told it's KVM. */
export function KvmView(props: SessionViewProps) {
  const shared = virtCore()
  return shared ? <shared.GuestsView {...props} hypervisor={KVM} /> : null
}
