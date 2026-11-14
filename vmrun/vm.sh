#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CBITPOS=51
RPB=1

DISK="$SCRIPT_DIR/dmcrypt-test.raw"

if [ ! -f "$DISK" ]; then
    truncate -s 64M "$DISK"
fi

# Default: kaslr
# Usage:
#   ./vm.sh
#   ./vm.sh kaslr
#   ./vm.sh dm_crypt
MODE="${1:-kaslr}"

case "$MODE" in
    kaslr)
        KERNEL="$SCRIPT_DIR/bzImage_kaslr"
        ;;
    dm_crypt|dmcrypt)
        KERNEL="$SCRIPT_DIR/bzImage_dm_crypt"
        ;;
    *)
        echo "Usage: $0 {kaslr|dm_crypt}" >&2
        exit 1
        ;;
esac

if [ ! -f "$KERNEL" ]; then
    echo "Kernel image not found: $KERNEL" >&2
    exit 1
fi

KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
DMCRYPT_CREATE="dm-crypt-test,,8,rw,0 131072 crypt aes-xts-plain64 ${KEY} 0 /dev/vda 0"

qemu-system-x86_64 \
  -enable-kvm \
  -nographic \
  -machine q35 -smp 1 -m 2G \
  -cpu EPYC-v4 \
  -machine confidential-guest-support=sev0,vmport=off \
  -object memory-backend-memfd,id=ram1,size=2G,share=true,prealloc=false \
  -machine memory-backend=ram1 \
  -object sev-snp-guest,id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=${RPB},kernel-hashes=off,policy=0x30000 \
  -drive file="$DISK",if=virtio,format=raw \
  -bios "$SCRIPT_DIR/OVMF.fd" \
  -kernel "$KERNEL" \
  -append "console=ttyS0 earlyprintk=serial loglevel=8 dm-mod.waitfor=/dev/vda dm-mod.create=\"${DMCRYPT_CREATE}\"" \
  -device virtio-serial