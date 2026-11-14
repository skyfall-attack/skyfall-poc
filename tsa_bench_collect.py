#!/usr/bin/env python3
"""
tsa_bench_collect.py

Userspace collector for tsa_bench_ioctl.c.

Sends a benchmark configuration to /dev/tsa_bench, watches dmesg for
BMK lines, and stores BMK,RESULT rows as JSONL.

Examples:

  sudo python3 tsa_bench_collect.py --bench 1 --out results.jsonl
  sudo python3 tsa_bench_collect.py --bench 1,3,6 --repeats 5 --out results.jsonl
  sudo python3 tsa_bench_collect.py --bench all --repeats 3 --out results.jsonl
  sudo python3 tsa_bench_collect.py --bench 4 --event-range 0x00:0xff --umask-range 0x00:0xff --out pmcs.jsonl
  sudo python3 tsa_bench_collect.py --bench 7 --out vmrun.jsonl --event-range 0x76:0x76 --default-secret-bits 64
  sudo python3 tsa_bench_collect.py --bench 9 --out stlf.jsonl
  sudo python3 tsa_bench_collect.py --bench 10 --event-range 0x76:0x76 --umask-range 0x00:0xff --sample 100 --repeats 100 --out result.jsonl
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
import queue
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

TSA_BENCH_MAX_LIST = 32

TSA_BENCH_1_ACCURACY_VS_SAMPLES  = 1 << 0
TSA_BENCH_2_SECRET_LENGTH        = 1 << 1
TSA_BENCH_3_WORKING_PMCS         = 1 << 2
TSA_BENCH_4_VIRT_VS_PHYS         = 1 << 3
TSA_BENCH_5_MITIGATION           = 1 << 4
TSA_BENCH_6_NEGATIVE_CONTROLS    = 1 << 5
TSA_BENCH_7_VMRUN                = 1 << 6
TSA_BENCH_9_4K_ALIAS_STLF        = 1 << 8
TSA_BENCH_10_1GIB_LEAK_RATE      = 1 << 9

TSA_ACCESS_VIRTUAL  = 1
TSA_ACCESS_PHYSICAL = 2
TSA_ACCESS_VMRUN    = 3

TSA_MIT_VERW      = 1 << 0
TSA_MIT_WBINVD    = 1 << 1
TSA_MIT_L1D_FLUSH = 1 << 2
TSA_MIT_CFLUSH    = 1 << 3

TSA_NEG_NO_TARGET_TLB_FLUSH  = 1 << 0
TSA_NEG_REP_MOVS             = 1 << 1
TSA_NEG_DIV_SQRT_PORT        = 1 << 2
TSA_NEG_VECTOR_MASKING       = 1 << 3
TSA_NEG_ADDRESS_TRANSLATION  = 1 << 4
TSA_NEG_STLF                 = 1 << 5

TSA_IOCTL_MAGIC          = ord("T")
TSA_IOCTL_NR_START_BENCH = 0x42

_IOC_NRBITS    = 8
_IOC_TYPEBITS  = 8
_IOC_SIZEBITS  = 14
_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT  + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_WRITE     = 1


def _ioc(direction: int, type_: int, nr: int, size: int) -> int:
    return (
        (direction << _IOC_DIRSHIFT)
        | (type_   << _IOC_TYPESHIFT)
        | (nr      << _IOC_NRSHIFT)
        | (size    << _IOC_SIZESHIFT)
    )


class TsaBenchArgs(ctypes.Structure):
    _fields_ = [
        ("run_id",                       ctypes.c_uint64),
        ("bench_mask",                   ctypes.c_uint32),
        ("repeats",                      ctypes.c_uint32),
        ("n_samples",                    ctypes.c_uint32),
        ("samples",                      ctypes.c_uint32 * TSA_BENCH_MAX_LIST),
        ("n_secret_bits",                ctypes.c_uint32),
        ("secret_bits",                  ctypes.c_uint32 * TSA_BENCH_MAX_LIST),
        ("event_start",                  ctypes.c_uint32),
        ("event_end",                    ctypes.c_uint32),
        ("umask_start",                  ctypes.c_uint32),
        ("umask_end",                    ctypes.c_uint32),
        ("accuracy_threshold_permille",  ctypes.c_uint32),
        ("mitigation_mask",              ctypes.c_uint32),
        ("access_mask",                  ctypes.c_uint32),
        ("negative_mask",                ctypes.c_uint32),
        ("default_samples",              ctypes.c_uint32),
        ("default_secret_bits",          ctypes.c_uint32),
        ("default_event",                ctypes.c_uint32),
    ]


TSA_IOCTL_START_BENCH = _ioc(
    _IOC_WRITE, TSA_IOCTL_MAGIC, TSA_IOCTL_NR_START_BENCH,
    ctypes.sizeof(TsaBenchArgs),
)

BENCH_MAP = {
    1: TSA_BENCH_1_ACCURACY_VS_SAMPLES,
    2: TSA_BENCH_2_SECRET_LENGTH,
    3: TSA_BENCH_3_WORKING_PMCS,
    4: TSA_BENCH_4_VIRT_VS_PHYS,
    5: TSA_BENCH_5_MITIGATION,
    6: TSA_BENCH_6_NEGATIVE_CONTROLS,
    7: TSA_BENCH_7_VMRUN,
    9: TSA_BENCH_9_4K_ALIAS_STLF,
    10: TSA_BENCH_10_1GIB_LEAK_RATE,
}

DEFAULT_SAMPLES     = [1, 2, 4, 8, 16, 32, 50, 64, 100, 128, 256, 512]
DEFAULT_SECRET_BITS = [32, 64, 128, 256, 512]

DEFAULT_QEMU_CMD = ["sudo", "taskset", "-c", "0", "./vmrun/vm.sh"]
QEMU_READY_MARKER = "[*] Writing RAX"


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def parse_int(value: str) -> int:
    return int(value, 0)


def parse_int_list(value: str) -> List[int]:
    return [parse_int(x.strip()) for x in value.split(",") if x.strip()]


def parse_range(value: str) -> Tuple[int, int]:
    if ":" not in value:
        v = parse_int(value)
        return v, v
    a, b = value.split(":", 1)
    return parse_int(a), parse_int(b)


def parse_bench_selection(value: str) -> int:
    value = value.strip().lower()
    if value == "all":
        mask = 0
        for bit in BENCH_MAP.values():
            mask |= bit
        return mask
    mask = 0
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        bench_id = int(item, 10)
        if bench_id not in BENCH_MAP:
            valid = ",".join(str(k) for k in sorted(BENCH_MAP))
            raise ValueError(f"invalid benchmark id: {bench_id}; expected one of {valid} or all")
        mask |= BENCH_MAP[bench_id]
    return mask


def fill_u32_array(dst, values: List[int]) -> int:
    n = min(len(values), TSA_BENCH_MAX_LIST)
    for i in range(n):
        dst[i] = int(values[i]) & 0xFFFFFFFF
    return n


def make_args(ns: argparse.Namespace) -> TsaBenchArgs:
    run_id = ns.run_id or int(time.time_ns())
    event_start, event_end = parse_range(ns.event_range)
    umask_start, umask_end = parse_range(ns.umask_range)

    args = TsaBenchArgs()
    args.run_id     = run_id
    args.bench_mask = parse_bench_selection(ns.bench)
    args.repeats    = ns.repeats

    samples     = parse_int_list(ns.samples)     if ns.samples     else DEFAULT_SAMPLES
    secret_bits = parse_int_list(ns.secret_bits) if ns.secret_bits else DEFAULT_SECRET_BITS

    args.n_samples     = fill_u32_array(args.samples,     samples)
    args.n_secret_bits = fill_u32_array(args.secret_bits, secret_bits)

    args.event_start = event_start
    args.event_end   = event_end
    args.umask_start = umask_start
    args.umask_end   = umask_end

    args.accuracy_threshold_permille = ns.accuracy_threshold_permille

    args.mitigation_mask = 0
    if ns.mit_verw:      args.mitigation_mask |= TSA_MIT_VERW
    if ns.mit_wbinvd:    args.mitigation_mask |= TSA_MIT_WBINVD
    if ns.mit_l1d_flush: args.mitigation_mask |= TSA_MIT_L1D_FLUSH
    if ns.mit_cflush:    args.mitigation_mask |= TSA_MIT_CFLUSH
    if args.mitigation_mask == 0:
        args.mitigation_mask = TSA_MIT_VERW | TSA_MIT_WBINVD | TSA_MIT_L1D_FLUSH | TSA_MIT_CFLUSH

    if args.bench_mask & TSA_BENCH_7_VMRUN:
        args.access_mask = TSA_ACCESS_VMRUN
    elif args.bench_mask & TSA_BENCH_4_VIRT_VS_PHYS:
        args.access_mask = TSA_ACCESS_PHYSICAL
    else:
        args.access_mask = TSA_ACCESS_VIRTUAL

    args.negative_mask = 0
    if ns.negative in ("all", "no-tlb-flush"):
        args.negative_mask |= TSA_NEG_NO_TARGET_TLB_FLUSH
    if ns.negative == "all":
        args.negative_mask |= (
            TSA_NEG_REP_MOVS | TSA_NEG_DIV_SQRT_PORT | TSA_NEG_VECTOR_MASKING
            | TSA_NEG_ADDRESS_TRANSLATION | TSA_NEG_STLF
        )

    args.default_samples     = ns.default_samples
    args.default_secret_bits = ns.default_secret_bits
    args.default_event       = parse_int(ns.default_event)
    return args


def parse_bmk_payload(line: str) -> Optional[Dict[str, object]]:
    idx = line.find("BMK,")
    if idx < 0:
        return None
    payload = line[idx:].strip()
    parts   = payload.split(",")
    if len(parts) < 2:
        return None

    record: Dict[str, object] = {"kind": parts[1]}
    for part in parts[2:]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key:
            continue
        if re.fullmatch(r"-?0x[0-9a-fA-F]+", value):
            record[key] = int(value, 16)
        elif re.fullmatch(r"-?\d+", value):
            record[key] = int(value, 10)
        else:
            record[key] = value
    return record



def drain_stream(stream, out_queue: "queue.Queue[str]") -> None:
    try:
        for line in stream:
            out_queue.put(line)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def wait_for_qemu_ready(
    proc: subprocess.Popen[str],
    output_queue: "queue.Queue[str]",
    timeout_s: float,
) -> None:
    """Wait until vm.sh/QEMU prints the VMRUN readiness marker.

    The QEMU output is consumed by a background thread but never forwarded to
    this script's stdout/stderr, so the benchmark console stays clean and QEMU
    cannot block on a full pipe.
    """
    deadline = time.time() + timeout_s if timeout_s > 0 else None

    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"QEMU process exited before ready marker: rc={proc.returncode}")

        if deadline is not None:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"timed out waiting for QEMU ready marker: {QEMU_READY_MARKER!r}"
                )
            wait_s = min(0.25, remaining)
        else:
            wait_s = 0.25

        try:
            line = output_queue.get(timeout=wait_s)
        except queue.Empty:
            continue

        if QEMU_READY_MARKER in line:
            return


def start_qemu_for_vmrun(ns: argparse.Namespace) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        ns.qemu_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    if not proc.stdout:
        kill_process_tree(proc)
        raise RuntimeError("failed to open QEMU stdout")

    output_queue: "queue.Queue[str]" = queue.Queue()
    threading.Thread(
        target=drain_stream,
        args=(proc.stdout, output_queue),
        daemon=True,
    ).start()

    try:
        wait_for_qemu_ready(proc, output_queue, ns.qemu_ready_timeout)
    except Exception:
        kill_process_tree(proc)
        raise
    return proc


def kill_process_tree(proc: Optional[subprocess.Popen[str]]) -> None:
    if proc is None or proc.poll() is not None:
        return

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)


def send_ioctl(device: str, args: TsaBenchArgs) -> None:
    fd = os.open(device, os.O_RDWR)
    try:
        fcntl.ioctl(fd, TSA_IOCTL_START_BENCH, args)
    finally:
        os.close(fd)


def write_jsonl(path: Path, obj: Dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")


# ------------------------------------------------------------------ #
# Collector                                                           #
# ------------------------------------------------------------------ #

def collect(ns: argparse.Namespace) -> int:
    args   = make_args(ns)
    run_id = int(args.run_id)

    out_path = Path(ns.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    qemu_proc: Optional[subprocess.Popen[str]] = None

    dmesg_proc = subprocess.Popen(
        ["dmesg", "--follow", "--human", "--decode"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if not dmesg_proc.stdout:
        raise RuntimeError("failed to open dmesg stdout")

    if args.bench_mask & TSA_BENCH_7_VMRUN:
        print("starting VMRUN/QEMU helper", flush=True)
        qemu_proc = start_qemu_for_vmrun(ns)
        print("VMRUN/QEMU helper is ready", flush=True)

    send_ioctl(ns.device, args)
    print(f"started run_id={run_id}; writing {out_path}", flush=True)

    selector      = selectors.DefaultSelector()
    selector.register(dmesg_proc.stdout, selectors.EVENT_READ)

    got_end       = False
    last_activity = time.time()
    timeout_s     = ns.timeout

    try:
        while not got_end:
            events = selector.select(timeout=1.0)
            now    = time.time()

            if not events:
                if timeout_s > 0 and now - last_activity > timeout_s:
                    print(f"timeout: no BMK output for {timeout_s:.0f}s; stopping",
                          file=sys.stderr)
                    break
                continue

            for key, _ in events:
                while True:
                    line = key.fileobj.readline()
                    if not line:
                        break

                    last_activity = now
                    record = parse_bmk_payload(line)
                    if record is None:
                        continue

                    record_run = record.get("run")
                    if record_run is not None and record_run != run_id:
                        continue

                    kind = record.get("kind")

                    if kind == "RESULT":
                        write_jsonl(out_path, record)

                    elif kind == "BENCH_END" and record_run == run_id:
                        print(
                            f"bench complete: bench={record.get('bench', '?')} "
                            f"bench_name={record.get('bench_name', 'unknown')}",
                            flush=True,
                        )

                    elif kind == "END" and record_run == run_id:
                        print(f"run complete run_id={run_id}; stopping collector",
                              flush=True)
                        got_end = True
                        break

    finally:
        selector.close()
        dmesg_proc.terminate()
        try:
            dmesg_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            dmesg_proc.kill()
        kill_process_tree(qemu_proc)

    print(f"done run_id={run_id}; results={out_path}", flush=True)
    return 0


# ------------------------------------------------------------------ #
# CLI                                                                 #
# ------------------------------------------------------------------ #

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Collect TSA benchmark data from /dev/tsa_bench")
    p.add_argument("--device",       default="/dev/tsa_bench")
    p.add_argument("--out",          required=True, help="output JSONL file")
    p.add_argument("--bench",        required=True, help="1, 1,3,6,7,9,10, or all")
    p.add_argument("--run-id",       type=lambda x: int(x, 0), default=0)
    p.add_argument("--repeats",      type=int, default=1)
    p.add_argument("--samples",      default="", help="comma-separated sample counts")
    p.add_argument("--secret-bits",  default="", help="comma-separated secret lengths in bits")
    p.add_argument("--default-samples",     type=int, default=100)
    p.add_argument("--default-secret-bits", type=int, default=32)
    p.add_argument("--default-event",       default="0x00")
    p.add_argument("--event-range", "--event", dest="event_range", default="0x00:0xfff")
    p.add_argument("--umask-range", "--umask", "--umasks", dest="umask_range", default="0x00:0xff")
    p.add_argument("--accuracy-threshold-permille", type=int, default=875)
    p.add_argument("--negative", choices=["all", "no-tlb-flush", "none"],  default="all")
    p.add_argument("--mit-verw",      action="store_true")
    p.add_argument("--mit-wbinvd",    action="store_true")
    p.add_argument("--mit-l1d-flush", action="store_true")
    p.add_argument("--mit-cflush",    action="store_true")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="seconds of silence before giving up; 0 disables")
    p.add_argument("--qemu-cmd", nargs="+", default=DEFAULT_QEMU_CMD,
                   help="command used before bench 7; default: sudo taskset -c 0 ./vmrun/vm.sh")
    p.add_argument("--qemu-ready-timeout", type=float, default=60.0,
                   help="seconds to wait for the QEMU ready marker before bench 7; 0 disables")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    ns     = parser.parse_args(argv)

    if os.geteuid() != 0:
        print("this collector must run as root", file=sys.stderr)
        return 1
    if not Path(ns.device).exists():
        print(f"device not found: {ns.device}", file=sys.stderr)
        return 1

    return collect(ns)


if __name__ == "__main__":
    raise SystemExit(main())
