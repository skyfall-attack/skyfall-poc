#include <linux/module.h>
#include "vmrun.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Vezzù");
MODULE_AUTHOR("Benedict Schlüter");
MODULE_DESCRIPTION("Hook for vmrun to enable VMRUN-based probing in the TSA-L1 benchmark module");


extern bool call_hook;
extern svm_sev_es_run_hook_t vmrun_sev_es;
extern svm_sev_es_run_hook_t svm_sev_es_run_hook;

extern svm_sev_es_run_singlestep_t svm_sev_es_run_singlestep;

u64 RAX_SECRET = 0xdeadbeefdeadbeefUL;
void* tsa_bench_args;
void* vmcb_save;

void vmrun(struct vcpu_svm *svm, bool spec_ctrl_intercepted, struct sev_es_save_area *hostsa)
{
    
    svm->vmcb->control.event_inj =  (1U << 31) | 
									(5U << 28) | 	// invalid type
									(1U << 11) |
									0x400; 

	svm->vmcb->control.event_inj_err = 0;
    vmrun_sev_es(svm, spec_ctrl_intercepted, hostsa);
}

void hook_vmrun(void* args, svm_sev_es_run_hook_t hook)
{
    tsa_bench_args = args;
    svm_sev_es_run_hook = hook;
    WRITE_ONCE(call_hook, true);
}

void unhook_vmrun(void)
{
    WRITE_ONCE(call_hook, false);
}

void enable_singlestep(void* args, svm_sev_es_run_singlestep_t singlestep_func)
{
    tsa_bench_args = args;
    svm_sev_es_run_singlestep = singlestep_func;
}
