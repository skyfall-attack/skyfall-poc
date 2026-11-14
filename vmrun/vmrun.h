#pragma once
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bits.h>

#include <asm/svm.h>
#include <asm/sev-common.h>

extern u64 RAX_SECRET;
extern void* tsa_bench_args;
extern void* vmcb_save;

#define VMSA_RAX_OFFSET 0x1F8 
#define VMSA_RIP_OFFSET 0x178 
#define VMSA_LSTAR_OFFSET 0x208
#define VMSA_XMM0_OFFSET 0x470
#define VMSA_XMM2_OFFSET 0x490

struct kvm_vmcb_info
{
    struct vmcb *ptr;
    unsigned long pa;
    int cpu;
    uint64_t asid_generation;
};

struct vmcb_save_area_cached {
	u64 efer;
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
};

struct vmcb_ctrl_area_cached
{
    u32 intercepts[MAX_INTERCEPT];
    u16 pause_filter_thresh;
    u16 pause_filter_count;
    u64 iopm_base_pa;
    u64 msrpm_base_pa;
    u64 tsc_offset;
    u32 asid;
    u8 tlb_ctl;
    u32 int_ctl;
    u32 int_vector;
    u32 int_state;
    u32 exit_code;
    u32 exit_code_hi;
    u64 exit_info_1;
    u64 exit_info_2;
    u32 exit_int_info;
    u32 exit_int_info_err;
    u64 nested_ctl;
    u32 event_inj;
    u32 event_inj_err;
    u64 next_rip;
    u64 nested_cr3;
    u64 virt_ext;
    u32 clean;
    u64 bus_lock_rip;
    union
    {
#if IS_ENABLED(CONFIG_HYPERV) || IS_ENABLED(CONFIG_KVM_HYPERV)
        struct hv_vmcb_enlightenments hv_enlightenments;
#endif
        u8 reserved_sw[32];
    };
};

struct svm_nested_state
{
    struct kvm_vmcb_info vmcb02;
    u64 hsave_msr;
    u64 vm_cr_msr;
    u64 vmcb12_gpa;
    u64 last_vmcb12_gpa;

    /*
     * The MSR permissions map used for vmcb02, which is the merge result
     * of vmcb01 and vmcb12
     */
    void *msrpm;

    /* A VMRUN has started but has not yet been performed, so
     * we cannot inject a nested vmexit yet.  */
    bool nested_run_pending;

    /* cache for control fields of the guest */
    struct vmcb_ctrl_area_cached ctl;

    /*
     * Note: this struct is not kept up-to-date while L2 runs; it is only
     * valid within nested_svm_vmrun.
     */
    struct vmcb_save_area_cached save;

    bool initialized;

    /*
     * Indicates whether MSR bitmap for L2 needs to be rebuilt due to
     * changes in MSR bitmap for L1 or switching to a different L2. Note,
     * this flag can only be used reliably in conjunction with a paravirt L1
     * which informs L0 whether any changes to MSR bitmap for L2 were done
     * on its side.
     */
    bool force_msr_bitmap_recalc;
};

struct vcpu_sev_es_state
{
    /* SEV-ES support */
    struct sev_es_save_area *vmsa;
    struct ghcb *ghcb;
    u8 valid_bitmap[16];
    struct kvm_host_map ghcb_map;
    bool received_first_sipi;
    unsigned int ap_reset_hold_type;

    /* SEV-ES scratch area support */
    u64 sw_scratch;
    void *ghcb_sa;
    u32 ghcb_sa_len;
    bool ghcb_sa_sync;
    bool ghcb_sa_free;

    /* SNP Page-State-Change buffer entries currently being processed */
    u16 psc_idx;
    u16 psc_inflight;
    bool psc_2m;

    u64 ghcb_registered_gpa;

    struct mutex snp_vmsa_mutex; /* Used to handle concurrent updates of VMSA. */
    gpa_t snp_vmsa_gpa;
    bool snp_ap_waiting_for_reset;
    bool snp_has_guest_vmsa;
};

struct vcpu_svm
{
    struct kvm_vcpu vcpu;
    /* vmcb always points at current_vmcb->ptr, it's purely a shorthand. */
    struct vmcb *vmcb;
    struct kvm_vmcb_info vmcb01;
    struct kvm_vmcb_info *current_vmcb;
    u32 asid;
    u32 sysenter_esp_hi;
    u32 sysenter_eip_hi;
    uint64_t tsc_aux;

    u64 msr_decfg;

    u64 next_rip;

    u64 spec_ctrl;

    u64 tsc_ratio_msr;
    /*
     * Contains guest-controlled bits of VIRT_SPEC_CTRL, which will be
     * translated into the appropriate L2_CFG bits on the host to
     * perform speculative control.
     */
    u64 virt_spec_ctrl;

    void *msrpm;

    ulong nmi_iret_rip;

    struct svm_nested_state nested;

    /* NMI mask value, used when vNMI is not enabled */
    bool nmi_masked;

    /*
     * True when NMIs are still masked but guest IRET was just intercepted
     * and KVM is waiting for RIP to change, which will signal that the
     * intercepted IRET was retired and thus NMI can be unmasked.
     */
    bool awaiting_iret_completion;

    /*
     * Set when KVM is awaiting IRET completion and needs to inject NMIs as
     * soon as the IRET completes (e.g. NMI is pending injection).  KVM
     * temporarily steals RFLAGS.TF to single-step the guest in this case
     * in order to regain control as soon as the NMI-blocking condition
     * goes away.
     */
    bool nmi_singlestep;
    u64 nmi_singlestep_guest_rflags;

    bool nmi_l1_to_l2;

    unsigned long soft_int_csbase;
    unsigned long soft_int_old_rip;
    unsigned long soft_int_next_rip;
    bool soft_int_injected;

    u32 ldr_reg;
    u32 dfr_reg;

    /* This is essentially a shadow of the vCPU's actual entry in the
     * Physical ID table that is programmed into the VMCB, i.e. that is
     * seen by the CPU.  If IPI virtualization is disabled, IsRunning is
     * only ever set in the shadow, i.e. is never propagated to the "real"
     * table, so that hardware never sees IsRunning=1.
     */
    u64 avic_physical_id_entry;

    /*
     * Per-vCPU list of irqfds that are eligible to post IRQs directly to
     * the vCPU (a.k.a. device posted IRQs, a.k.a. IRQ bypass).  The list
     * is used to reconfigure IRTEs when the vCPU is loaded/put (to set the
     * target pCPU), when AVIC is toggled on/off (to (de)activate bypass),
     * and if the irqfd becomes ineligible for posting (to put the IRTE
     * back into remapped mode).
     */
    struct list_head ir_list;
    spinlock_t ir_list_lock;

    struct vcpu_sev_es_state sev_es;

    bool guest_state_loaded;

    bool x2avic_msrs_intercepted;

    /* Guest GIF value, used when vGIF is not enabled */
    bool guest_gif;
};

typedef void (*svm_sev_es_run_hook_t)(struct vcpu_svm *svm,
                                      bool spec_ctrl_intercepted,
                                      struct sev_es_save_area *hostsa);

typedef void (*svm_sev_es_run_singlestep_t)(void);

void vmrun(struct vcpu_svm *svm, bool spec_ctrl_intercepted, struct sev_es_save_area *hostsa);

void hook_vmrun(void* args, svm_sev_es_run_hook_t hook);
void unhook_vmrun(void);

void enable_singlestep(void* args, svm_sev_es_run_singlestep_t singlestep_func);