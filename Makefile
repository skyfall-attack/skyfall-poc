BMARKS_NAME := tsa_bench_ioctl
BMARKS_MAIN := tsa_bench_ioctl_main
VMSAVE_UTAG_NAME := tsa_vmsave_utag
MICROCODE_NAME := microcode
SMM_NAME := smm

CPU_MODEL_NAME := $(shell lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -n1)

ifeq ($(CPU_MODEL_NAME),AMD EPYC 7313 16-Core Processor)
ccflags-y += -DTSA_4LEVEL_PAGING
endif

# Compile benchmark, VMSAVE/uTag, microcode, and SMM test modules
obj-m += $(BMARKS_NAME).o
obj-m += $(VMSAVE_UTAG_NAME).o
obj-m += $(MICROCODE_NAME).o
obj-m += $(SMM_NAME).o

# tsa_bench_ioctl.ko is linked from tsa_bench_ioctl_main.o + vmrun/vmrun.o
$(BMARKS_NAME)-y := $(BMARKS_MAIN).o vmrun/vmrun.o

# Tell objtool to completely ignore these module objects
OBJECT_FILES_NON_STANDARD_$(BMARKS_MAIN).o := y
OBJECT_FILES_NON_STANDARD_vmrun/vmrun.o := y
OBJECT_FILES_NON_STANDARD_$(VMSAVE_UTAG_NAME).o := y
OBJECT_FILES_NON_STANDARD_$(MICROCODE_NAME).o := y
OBJECT_FILES_NON_STANDARD_$(SMM_NAME).o := y

CFLAGS_$(BMARKS_MAIN).o += -msse -msse2
CFLAGS_vmrun/vmrun.o += -msse -msse2
CFLAGS_$(VMSAVE_UTAG_NAME).o += -msse -msse2
CFLAGS_$(MICROCODE_NAME).o += -msse -msse2
CFLAGS_$(SMM_NAME).o += -msse -msse2

ifneq ($(CPU_MODEL_NAME),AMD EPYC 7313 16-Core Processor)
CFLAGS_$(BMARKS_MAIN).o += -mavx512f -mavx512bw
CFLAGS_vmrun/vmrun.o += -mavx512f -mavx512bw
CFLAGS_$(VMSAVE_UTAG_NAME).o += -mavx512f -mavx512bw
CFLAGS_$(MICROCODE_NAME).o += -mavx512f -mavx512bw
CFLAGS_$(SMM_NAME).o += -mavx512f -mavx512bw
endif

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean \
	insmod-bmarks insmod-vmsave-utag insmod-microcode insmod-smm \
	rmmod-bmarks rmmod-vmsave-utag rmmod-microcode rmmod-smm \
	print-cpu

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

print-cpu:
	@echo "CPU_MODEL_NAME=$(CPU_MODEL_NAME)"
	@echo "ccflags-y=$(ccflags-y)"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

insmod-bmarks: all
	@echo "[+] Clearing kernel ring buffer (dmesg -C)..."
	@sudo dmesg -C
	@echo "[+] Removing old benchmark module if it exists..."
	@-sudo rmmod -f $(BMARKS_NAME) 2>/dev/null || true
	@echo "[+] Inserting $(BMARKS_NAME).ko"
	@sudo insmod $(BMARKS_NAME).ko

insmod-vmsave-utag: all
	@echo "[+] Clearing kernel ring buffer (dmesg -C)..."
	@sudo dmesg -C
	@echo "[+] Removing old VMSAVE/uTag module if it exists..."
	@-sudo rmmod -f $(VMSAVE_UTAG_NAME) 2>/dev/null || true
	@echo "[+] Inserting $(VMSAVE_UTAG_NAME).ko"
	@sudo insmod $(VMSAVE_UTAG_NAME).ko

insmod-microcode: all
	@echo "[+] Clearing kernel ring buffer (dmesg -C)..."
	@sudo dmesg -C
	@echo "[+] Removing old microcode module if it exists..."
	@-sudo rmmod -f $(MICROCODE_NAME) 2>/dev/null || true
	@echo "[+] Inserting $(MICROCODE_NAME).ko"
	@sudo insmod $(MICROCODE_NAME).ko

insmod-smm: all
	@echo "[+] Clearing kernel ring buffer (dmesg -C)..."
	@sudo dmesg -C
	@echo "[+] Removing old SMM module if it exists..."
	@-sudo rmmod -f $(SMM_NAME) 2>/dev/null || true
	@echo "[+] Inserting $(SMM_NAME).ko"
	@sudo insmod $(SMM_NAME).ko

rmmod-bmarks:
	@echo "[+] Removing $(BMARKS_NAME)..."
	@sudo rmmod -f $(BMARKS_NAME)

rmmod-vmsave-utag:
	@echo "[+] Removing $(VMSAVE_UTAG_NAME)..."
	@sudo rmmod -f $(VMSAVE_UTAG_NAME)

rmmod-microcode:
	@echo "[+] Removing $(MICROCODE_NAME)..."
	@sudo rmmod -f $(MICROCODE_NAME)

rmmod-smm:
	@echo "[+] Removing $(SMM_NAME)..."
	@sudo rmmod -f $(SMM_NAME)
