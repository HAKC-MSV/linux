#include <linux/hakc/hakc.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "../vmx/vmx.h"
#include "kvm_transfer.h"

/* utility macros for writing custom transfers */
#define transfer_field(name,size)  name = hakc_transfer_to_clique(              \
                                                HAKC_GET_SAFE_PTR(name), size,  \
                                                compartment, color, false)

#define null_check(name) if(!name) return name

struct vcpu_vmx *hakc_transfer_vcpu_vmx(struct vcpu_vmx *vmxp,
                        hakc_compartment_id_t compartment,
                        clique_color_t color)
{
        null_check(vmxp);

        vmxp = HAKC_GET_SAFE_PTR(vmxp);
        vmxp->loaded_vmcs = HAKC_GET_SAFE_PTR(vmxp->loaded_vmcs);
        vmxp->loaded_vmcs= hakc_transfer_to_clique(vmxp->loaded_vmcs,sizeof(struct loaded_vmcs),
                                compartment,color,false);

        return hakc_transfer_to_clique(vmxp, sizeof(*vmxp),
                                        compartment, color, false);
}
EXPORT_SYMBOL_NS(hakc_transfer_vcpu_vmx, "HAKC_KVM");

struct kvm_run *hakc_transfer_kvm_run(struct kvm_run *kvm_runp,
                        hakc_compartment_id_t compartment,
                        clique_color_t color)
{
        null_check(kvm_runp);

        kvm_runp = HAKC_GET_SAFE_PTR(kvm_runp);

        return hakc_transfer_to_clique(kvm_runp, sizeof(*kvm_runp),
                                        compartment, color, false);
}
EXPORT_SYMBOL_NS(hakc_transfer_kvm_run, "HAKC_KVM");

struct kvm_vcpu *hakc_transfer_kvm_vcpu(struct kvm_vcpu *kvm_vcpup,
                        hakc_compartment_id_t compartment,
                        clique_color_t color)
{
        null_check(kvm_vcpup);
        kvm_vcpup = HAKC_GET_SAFE_PTR(kvm_vcpup);

#if 0
        kvm_vcpup->kvm = hakc_transfer_kvm(kvm_vcpup->kvm, compartment, color);
#if 1
        kvm_vcpup->run = hakc_transfer_kvm_run(kvm_vcpup->run, compartment,
                                                color);
#endif
#endif

//      return hakc_transfer_to_clique(kvm_vcpup, sizeof(*kvm_vcpup),
///                                     compartment, color, false);
        return (struct kvm_vcpu *)hakc_transfer_vcpu_vmx((struct vcpu_vmx*)kvm_vcpup, compartment, color);
}
EXPORT_SYMBOL_NS(hakc_transfer_kvm_vcpu, "HAKC_KVM");

struct kvm *hakc_transfer_kvm(struct kvm *kvmp,
                        hakc_compartment_id_t compartment,
                        clique_color_t color)
{
        null_check(kvmp);

        kvmp = HAKC_GET_SAFE_PTR(kvmp);
#if 0
        //struct mm_struct* mm;
        kvmp->mm = hakc_transfer_to_clique(kvmp->mm, sizeof(*(kvmp->mm)),
                                                compartment, color, false);
#if 1
        //struct kvm_memslots __rcu *memslots[KVM_ADDRESS_SPACE_NUM];
        for (int i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
                kvmp->memslots[i] = hakc_transfer_to_clique(kvmp->memslots[i],
                                                sizeof(struct kvm_memslots),
                                                compartment, color, false);
        }

        //struct kvm_io_bus __rcu *buses[KVM_NR_BUSES];
        for (int i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
                kvmp->buses[i] = hakc_transfer_to_clique(kvmp->buses[i],
                                                sizeof(struct kvm_io_bus),
                                                compartment, color, false);
        }
#endif
#endif

        return hakc_transfer_to_clique(kvmp, sizeof(*kvmp), compartment, color, false);
}
EXPORT_SYMBOL_NS(hakc_transfer_kvm, "HAKC_KVM");
