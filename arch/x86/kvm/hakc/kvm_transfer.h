#ifndef __HAKC_KVM_TRANSFER_H
#define __HAKC_KVM_TRANSFER_H

#include <linux/hakc/hakc.h>

struct vcpu_vmx *hakc_transfer_vcpu_vmx(struct vcpu_vmx *vmxp,
                        hakc_compartment_id_t compartment,
                        clique_color_t color);

struct kvm_run *hakc_transfer_kvm_run(struct kvm_run *kvm_runp,
                        hakc_compartment_id_t compartment,
                        clique_color_t color);

struct kvm_vcpu *hakc_transfer_kvm_vcpu(struct kvm_vcpu *kvm_vcpup,
                        hakc_compartment_id_t compartment,
                        clique_color_t color);

struct kvm *hakc_transfer_kvm(struct kvm *kvmp,
                        hakc_compartment_id_t compartment,
                        clique_color_t color);

#endif // __HAKC_KVM_TRANSFER_H
