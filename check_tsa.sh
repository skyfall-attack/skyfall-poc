#!/usr/bin/env bash
set -euo pipefail

LEAF="0x80000021"

if ! command -v cpuid >/dev/null 2>&1; then
    echo "error: 'cpuid' tool not found"
    echo "install it with: sudo apt install cpuid"
    exit 1
fi

family_dec=$(awk -F: '/^cpu family/ { gsub(/ /, "", $2); print $2; exit }' /proc/cpuinfo)

if [[ -z "${family_dec:-}" ]]; then
    echo "error: could not read CPU family from /proc/cpuinfo"
    exit 1
fi

family_hex=$(printf "0x%x" "$family_dec")

echo "CPU family: $family_dec ($family_hex)"
echo

# AMD states that only Family 19h CPUs are vulnerable to TSA.
# Therefore, non-Family-19h CPUs are treated as not vulnerable,
# even if the CPUID TSA_*_NO bits are not set.
if (( family_dec != 0x19 )); then
    echo "TSA-SQ: NOT vulnerable     AMD: only Family 19h CPUs are vulnerable to TSA"
    echo "TSA-L1: NOT vulnerable     AMD: only Family 19h CPUs are vulnerable to TSA"
    exit 0
fi

line=$(cpuid -r -l "$LEAF" | grep -m1 "$LEAF" || true)

if [[ -z "$line" ]]; then
    echo "error: CPUID leaf $LEAF not supported or cpuid output unexpected"
    echo
    echo "TSA-SQ: vulnerable/unknown Family 19h CPU without readable TSA_SQ_NO bit"
    echo "TSA-L1: vulnerable/unknown Family 19h CPU without readable TSA_L1_NO bit"
    exit 1
fi

ecx=$(echo "$line" | sed -n 's/.*ecx=\(0x[0-9a-fA-F]*\).*/\1/p')

if [[ -z "$ecx" ]]; then
    echo "error: could not parse ECX from cpuid output:"
    echo "$line"
    exit 1
fi

ecx_val=$((ecx))

tsa_sq_no=$(( (ecx_val >> 1) & 1 ))
tsa_l1_no=$(( (ecx_val >> 2) & 1 ))

echo "CPUID Fn8000_0021 ECX = $ecx"
echo

if [[ "$tsa_sq_no" -eq 1 ]]; then
    echo "TSA-SQ: NOT vulnerable     CPUID ECX[1] TSA_SQ_NO=1"
else
    echo "TSA-SQ: vulnerable/unknown CPUID ECX[1] TSA_SQ_NO=0"
fi

if [[ "$tsa_l1_no" -eq 1 ]]; then
    echo "TSA-L1: NOT vulnerable     CPUID ECX[2] TSA_L1_NO=1"
else
    echo "TSA-L1: vulnerable/unknown CPUID ECX[2] TSA_L1_NO=0"
fi