// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <linux/preempt.h>
#include <linux/delay.h>
#include <asm/io.h>

#include <asm/msr.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>
#include <asm/special_insns.h>
#include <asm/barrier.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Vezzù");
MODULE_AUTHOR("Benedict Schlüter");
MODULE_DESCRIPTION("VMSAVE physical-uTag L1 eviction experiment");

#define ITERATIONS          1000
#define TEST_OFFSET         0x610
#define VA_SEARCH_PAGES     0x20000UL

#define MY_PMC_IDX          0
#define MY_PERFEVTSEL_MSR   (0xc0010200ULL + MY_PMC_IDX * 2)
#define MY_PERFCTR_MSR      (0xc0010201ULL + MY_PMC_IDX * 2)

/*
 * Same PMC config style as your snippet.
 * Make sure this event/umask is correct for the CPU you run on.
 */
#define MY_PERFEVTSEL_VAL \
    ((0x60ULL)        | \
     (0x80ULL << 8)   | \
     (1ULL    << 17)  | \
     (1ULL    << 22)  | \
     (2ULL    << 40))

static int cpu = -1;
module_param(cpu, int, 0444);
MODULE_PARM_DESC(cpu, "CPU on which to run the experiment, -1 = current CPU");

static unsigned long vmsave_page;
static unsigned long equal_page;
static unsigned long diff_page;

static unsigned long vmsave_phys;
static unsigned long equal_phys;
static unsigned long diff_phys;

static unsigned long equal_va;
static unsigned long diff_va;

#define CR3_ADDR_MASK (~0xfffUL)

#ifdef TSA_4LEVEL_PAGING
#define TSA_VA_BASE 0xffffc90040000000UL
#else
#define TSA_VA_BASE 0xff11000000000000UL
#endif

static __always_inline void mfence_lfence(void)
{
    asm volatile("mfence\n\tlfence" ::: "memory");
}

static __always_inline void flush_cache_line_fenced(const void *addr)
{
    asm volatile("clflush (%0)" :: "r"(addr) : "memory");
    mfence_lfence();
}

static void setup_l1miss_pmc(void)
{
    wrmsrl(MY_PERFCTR_MSR, 0ULL);
    wrmsrl(MY_PERFEVTSEL_MSR, MY_PERFEVTSEL_VAL);
}

#define PMC_BARRIER()                              \
    asm volatile(                                  \
        "mfence\n\t"                               \
        "mov $0x80000005, %%eax\n\t"               \
        "cpuid\n\t"                                \
        :                                          \
        :                                          \
        : "eax", "ebx", "ecx", "edx", "memory")

static __always_inline u64 read_pmc(void)
{
    u32 lo, hi;

    asm volatile("rdmsr"
                 : "=a"(lo), "=d"(hi)
                 : "c"((u32)MY_PERFCTR_MSR)
                 : "memory");

    return ((u64)hi << 32) | lo;
}

static __always_inline bool is_l1_miss(const u8 *addr)
{
    u64 before, after;
    volatile u8 val;

    preempt_disable();

    PMC_BARRIER();
    before = read_pmc();

    asm volatile("movb (%1), %0"
                 : "=r"(val)
                 : "r"(addr)
                 : "memory");

    after = read_pmc();
    PMC_BARRIER();

    preempt_enable();

    return (after - before) > 0;
}

static __always_inline u64 measure_access_time(const u8 *addr)
{
    u32 lo_start, hi_start;
    u32 lo_end, hi_end;
    u32 aux;
    volatile u8 value;

    preempt_disable();

    asm volatile("mfence\n\tlfence" ::: "memory");

    asm volatile("rdtscp"
                 : "=a"(lo_start), "=d"(hi_start), "=c"(aux)
                 :
                 : "memory");

    asm volatile("lfence" ::: "memory");

    asm volatile("movb (%1), %0"
                 : "=r"(value)
                 : "r"(addr)
                 : "memory");

    asm volatile("lfence" ::: "memory");

    asm volatile("rdtscp"
                 : "=a"(lo_end), "=d"(hi_end), "=c"(aux)
                 :
                 : "memory");

    asm volatile("mfence" ::: "memory");

    preempt_enable();

    return (((u64)hi_end << 32) | lo_end) -
           (((u64)hi_start << 32) | lo_start);
}

#define GET_BIT(x, bit) ((((u64)(x)) >> (bit)) & 1ULL)

static u64 calculate_zen_utag(u64 va)
{
    u64 u0 = GET_BIT(va, 12) ^ GET_BIT(va, 13) ^ GET_BIT(va, 14) ^
             GET_BIT(va, 15) ^ GET_BIT(va, 16) ^ GET_BIT(va, 17) ^
             GET_BIT(va, 18) ^ GET_BIT(va, 19) ^ GET_BIT(va, 20) ^
             GET_BIT(va, 21) ^ GET_BIT(va, 22) ^ GET_BIT(va, 23) ^
             GET_BIT(va, 24) ^ GET_BIT(va, 25) ^ GET_BIT(va, 26) ^
             GET_BIT(va, 27);

    u64 u1 = GET_BIT(va, 13) ^ GET_BIT(va, 26);
    u64 u2 = GET_BIT(va, 14) ^ GET_BIT(va, 25);
    u64 u3 = GET_BIT(va, 19) ^ GET_BIT(va, 24);
    u64 u4 = GET_BIT(va, 18) ^ GET_BIT(va, 23);
    u64 u5 = GET_BIT(va, 17) ^ GET_BIT(va, 22);
    u64 u6 = GET_BIT(va, 16) ^ GET_BIT(va, 21);
    u64 u7 = GET_BIT(va, 15) ^ GET_BIT(va, 20);

    return (u0 << 0) | (u1 << 1) | (u2 << 2) | (u3 << 3) |
           (u4 << 4) | (u5 << 5) | (u6 << 6) | (u7 << 7);
}

static void invlpg_addr(unsigned long va)
{
    asm volatile("invlpg (%0)" :: "r"(va) : "memory");
    asm volatile("mfence\n\tlfence" ::: "memory");
}

#ifdef TSA_4LEVEL_PAGING

static bool manual_va_is_free(unsigned long virt_addr)
{
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;

    pml4 = (unsigned long *)__va(read_cr3_pa() & CR3_ADDR_MASK);

    index4 = (virt_addr >> 39) & 0x1ff;
    index3 = (virt_addr >> 30) & 0x1ff;
    index2 = (virt_addr >> 21) & 0x1ff;
    index1 = (virt_addr >> 12) & 0x1ff;

    if (!(pml4[index4] & _PAGE_PRESENT))
        return true;

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!(pdp[index3] & _PAGE_PRESENT))
        return true;

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!(pd[index2] & _PAGE_PRESENT))
        return true;

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    return !(pt[index1] & _PAGE_PRESENT);
}

static int map_physical_to_virtual(unsigned long phys_addr,
                                   unsigned long virt_addr,
                                   u64 additional_pte_flags)
{
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;

    pml4 = (unsigned long *)__va(read_cr3_pa() & CR3_ADDR_MASK);

    index4 = (virt_addr >> 39) & 0x1ff;
    index3 = (virt_addr >> 30) & 0x1ff;
    index2 = (virt_addr >> 21) & 0x1ff;
    index1 = (virt_addr >> 12) & 0x1ff;

    if (!(pml4[index4] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pml4[index4] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);

    if (!(pdp[index3] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pdp[index3] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);

    if (!(pd[index2] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pd[index2] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);

    pt[index1] = (phys_addr & PAGE_MASK) |
                 _PAGE_PRESENT |
                 _PAGE_RW |
                 additional_pte_flags;

    smp_wmb();
    invlpg_addr(virt_addr);

    return 0;
}

static void unmap_manual_page(unsigned long virt_addr)
{
    unsigned long *pml4, *pdp, *pd, *pt;
    unsigned long index4, index3, index2, index1;

    if (!virt_addr)
        return;

    pml4 = (unsigned long *)__va(read_cr3_pa() & CR3_ADDR_MASK);

    index4 = (virt_addr >> 39) & 0x1ff;
    index3 = (virt_addr >> 30) & 0x1ff;
    index2 = (virt_addr >> 21) & 0x1ff;
    index1 = (virt_addr >> 12) & 0x1ff;

    if (!(pml4[index4] & _PAGE_PRESENT))
        return;

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!(pdp[index3] & _PAGE_PRESENT))
        return;

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!(pd[index2] & _PAGE_PRESENT))
        return;

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    pt[index1] = 0;

    smp_wmb();
    invlpg_addr(virt_addr);
}

#else

static bool manual_va_is_free(unsigned long virt_addr)
{
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;

    pml5 = (unsigned long *)__va(read_cr3_pa() & CR3_ADDR_MASK);

    index5 = (virt_addr >> 48) & 0x1ff;
    index4 = (virt_addr >> 39) & 0x1ff;
    index3 = (virt_addr >> 30) & 0x1ff;
    index2 = (virt_addr >> 21) & 0x1ff;
    index1 = (virt_addr >> 12) & 0x1ff;

    if (!(pml5[index5] & _PAGE_PRESENT))
        return true;

    pml4 = (unsigned long *)__va(pml5[index5] & PAGE_MASK);
    if (!(pml4[index4] & _PAGE_PRESENT))
        return true;

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!(pdp[index3] & _PAGE_PRESENT))
        return true;

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!(pd[index2] & _PAGE_PRESENT))
        return true;

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    return !(pt[index1] & _PAGE_PRESENT);
}

static int map_physical_to_virtual(unsigned long phys_addr,
                                   unsigned long virt_addr,
                                   u64 additional_pte_flags)
{
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;

    pml5 = (unsigned long *)__va(read_cr3_pa() & CR3_ADDR_MASK);

    index5 = (virt_addr >> 48) & 0x1ff;
    index4 = (virt_addr >> 39) & 0x1ff;
    index3 = (virt_addr >> 30) & 0x1ff;
    index2 = (virt_addr >> 21) & 0x1ff;
    index1 = (virt_addr >> 12) & 0x1ff;

    if (!(pml5[index5] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pml5[index5] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pml4 = (unsigned long *)__va(pml5[index5] & PAGE_MASK);

    if (!(pml4[index4] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pml4[index4] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);

    if (!(pdp[index3] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pdp[index3] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);

    if (!(pd[index2] & _PAGE_PRESENT)) {
        unsigned long page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!page)
            return -ENOMEM;

        pd[index2] = __pa(page) | _PAGE_PRESENT | _PAGE_RW;
    }

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);

    pt[index1] = (phys_addr & PAGE_MASK) |
                 _PAGE_PRESENT |
                 _PAGE_RW |
                 additional_pte_flags;

    smp_wmb();
    invlpg_addr(virt_addr);

    return 0;
}

static void unmap_manual_page(unsigned long virt_addr)
{
    unsigned long *pml5, *pml4, *pdp, *pd, *pt;
    unsigned long index5, index4, index3, index2, index1;

    if (!virt_addr)
        return;

    pml5 = (unsigned long *)__va(read_cr3_pa() & CR3_ADDR_MASK);

    index5 = (virt_addr >> 48) & 0x1ff;
    index4 = (virt_addr >> 39) & 0x1ff;
    index3 = (virt_addr >> 30) & 0x1ff;
    index2 = (virt_addr >> 21) & 0x1ff;
    index1 = (virt_addr >> 12) & 0x1ff;

    if (!(pml5[index5] & _PAGE_PRESENT))
        return;

    pml4 = (unsigned long *)__va(pml5[index5] & PAGE_MASK);
    if (!(pml4[index4] & _PAGE_PRESENT))
        return;

    pdp = (unsigned long *)__va(pml4[index4] & PAGE_MASK);
    if (!(pdp[index3] & _PAGE_PRESENT))
        return;

    pd = (unsigned long *)__va(pdp[index3] & PAGE_MASK);
    if (!(pd[index2] & _PAGE_PRESENT))
        return;

    pt = (unsigned long *)__va(pd[index2] & PAGE_MASK);
    pt[index1] = 0;

    smp_wmb();
    invlpg_addr(virt_addr);
}

#endif

static int find_probe_vas(unsigned long target_phys_utag)
{
    unsigned long va;
    bool found_equal = false;
    bool found_diff = false;

    for (va = TSA_VA_BASE;
         va < TSA_VA_BASE + VA_SEARCH_PAGES * PAGE_SIZE;
         va += PAGE_SIZE) {

        u64 tag;

        if (!manual_va_is_free(va))
            continue;

        tag = calculate_zen_utag(va);

        if (!found_equal && tag == target_phys_utag) {
            equal_va = va;
            found_equal = true;
            continue;
        }

        if (!found_diff && tag != target_phys_utag) {
            diff_va = va;
            found_diff = true;
            continue;
        }

        if (found_equal && found_diff)
            break;
    }

    if (!found_equal || !found_diff)
        return -ENOENT;

    return 0;
}

static void prepare_line_in_l1(const u8 *addr)
{
    volatile u8 val;

    flush_cache_line_fenced(addr);

    asm volatile("movb (%1), %0"
                 : "=r"(val)
                 : "r"(addr)
                 : "memory");

    asm volatile("lfence" ::: "memory");
}

static __always_inline void do_vmsave(unsigned long pa)
{
    asm volatile("vmsave %0"
                 :
                 : "a"(pa)
                 : "memory");
    asm volatile("lfence" ::: "memory");
}

static void run_case(const char *name, const u8 *addr)
{
    u64 hits = 0;
    u64 misses = 0;
    u64 total_time = 0;
    int i;

    for (i = 0; i < ITERATIONS; i++) {
        bool miss;
        u64 t;

        /*
         * Bring the probe line into L1, execute VMSAVE to the unrelated
         * physical VMSAVE page, then check whether the probe line missed.
         */
        prepare_line_in_l1(addr);

        do_vmsave(vmsave_phys);

        miss = is_l1_miss(addr);
        misses += miss;
        hits += !miss;

        /*
         * Separate timing measurement.
         */
        prepare_line_in_l1(addr);

        do_vmsave(vmsave_phys);

        t = measure_access_time(addr);
        total_time += t;
    }

    pr_info("%-42s VA=0x%lx PA=0x%lx uTag(VA)=0x%llx avg=%llu cycles hits=%llu misses=%llu iter=%u\n",
            name,
            (unsigned long)addr & PAGE_MASK,
            virt_to_phys((void *)((unsigned long)addr & PAGE_MASK)),
            calculate_zen_utag((unsigned long)addr),
            total_time / ITERATIONS,
            hits,
            misses,
            ITERATIONS);
}

static void run_baseline(const char *name, const u8 *addr)
{
    u64 hits = 0;
    u64 misses = 0;
    u64 total_time = 0;
    int i;

    for (i = 0; i < ITERATIONS; i++) {
        bool miss;
        u64 t;

        prepare_line_in_l1(addr);

        /*
         * No VMSAVE here. This should mostly stay L1-hot.
         */
        asm volatile("lfence" ::: "memory");

        miss = is_l1_miss(addr);
        misses += miss;
        hits += !miss;

        prepare_line_in_l1(addr);
        t = measure_access_time(addr);
        total_time += t;
    }

    pr_info("%-42s VA=0x%lx uTag(VA)=0x%llx avg=%llu cycles hits=%llu misses=%llu iter=%u\n",
            name,
            (unsigned long)addr & PAGE_MASK,
            calculate_zen_utag((unsigned long)addr),
            total_time / ITERATIONS,
            hits,
            misses,
            ITERATIONS);
}

static long run_experiment_on_cpu(void *unused)
{
    u8 *equal_addr;
    u8 *diff_addr;

    setup_l1miss_pmc();

    memset((void *)vmsave_page, 0, PAGE_SIZE);
    memset((void *)equal_page, 0xaa, PAGE_SIZE);
    memset((void *)diff_page, 0xbb, PAGE_SIZE);

    equal_addr = (u8 *)(equal_va + TEST_OFFSET);
    diff_addr  = (u8 *)(diff_va + TEST_OFFSET);

    pr_info("running on CPU %d\n", smp_processor_id());
    pr_info("vmsave_page VA=0x%lx PA=0x%lx uTag(PA)=0x%llx\n",
            vmsave_page,
            vmsave_phys,
            calculate_zen_utag(vmsave_phys));

    pr_info("equal probe VA=0x%lx PA=0x%lx uTag(VA)=0x%llx\n",
            equal_va,
            equal_phys,
            calculate_zen_utag(equal_va));

    pr_info("diff  probe VA=0x%lx PA=0x%lx uTag(VA)=0x%llx\n",
            diff_va,
            diff_phys,
            calculate_zen_utag(diff_va));

    run_baseline("baseline equal uTag, no VMSAVE", equal_addr);
    run_case("VMSAVE, uTag(VA) == uTag(PA)", equal_addr);

    run_baseline("baseline diff uTag, no VMSAVE", diff_addr);
    run_case("VMSAVE, uTag(VA) != uTag(PA)", diff_addr);

    return 0;
}

static int __init tsa_vmsave_utag_init(void)
{
    int ret;
    int target_cpu;

    pr_info("loading tsa_vmsave_utag\n");

    vmsave_page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
    equal_page  = __get_free_page(GFP_KERNEL | __GFP_ZERO);
    diff_page   = __get_free_page(GFP_KERNEL | __GFP_ZERO);

    if (!vmsave_page || !equal_page || !diff_page) {
        pr_err("failed to allocate pages\n");
        ret = -ENOMEM;
        goto fail;
    }

    vmsave_phys = virt_to_phys((void *)vmsave_page);
    equal_phys  = virt_to_phys((void *)equal_page);
    diff_phys   = virt_to_phys((void *)diff_page);

    ret = find_probe_vas(calculate_zen_utag(vmsave_phys));
    if (ret) {
        pr_err("failed to find equal/diff uTag virtual addresses\n");
        goto fail;
    }

    ret = map_physical_to_virtual(equal_phys, equal_va, 0);
    if (ret) {
        pr_err("failed to map equal_va\n");
        goto fail;
    }

    ret = map_physical_to_virtual(diff_phys, diff_va, 0);
    if (ret) {
        pr_err("failed to map diff_va\n");
        goto fail;
    }

    target_cpu = cpu;
    if (target_cpu < 0)
        target_cpu = smp_processor_id();

    if (target_cpu < 0 || target_cpu >= nr_cpu_ids || !cpu_online(target_cpu)) {
        pr_err("invalid/offline CPU %d\n", target_cpu);
        ret = -EINVAL;
        goto fail;
    }

    ret = work_on_cpu(target_cpu, run_experiment_on_cpu, NULL);
    if (ret)
        pr_err("experiment failed: %d\n", ret);

    return ret;

fail:
    unmap_manual_page(equal_va);
    unmap_manual_page(diff_va);

    if (vmsave_page)
        free_page(vmsave_page);
    if (equal_page)
        free_page(equal_page);
    if (diff_page)
        free_page(diff_page);

    return ret;
}

static void __exit tsa_vmsave_utag_exit(void)
{
    pr_info("unloading tsa_vmsave_utag\n");

    unmap_manual_page(equal_va);
    unmap_manual_page(diff_va);

    if (vmsave_page)
        free_page(vmsave_page);
    if (equal_page)
        free_page(equal_page);
    if (diff_page)
        free_page(diff_page);
}

module_init(tsa_vmsave_utag_init);
module_exit(tsa_vmsave_utag_exit);