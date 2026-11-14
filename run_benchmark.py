from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
import sys
import time
from pathlib import Path
from collections import Counter
from statistics import harmonic_mean, median
from typing import Any, Dict, List, Optional, Set, Tuple


COLLECTOR = Path("./tsa_bench_collect.py")

RESULTS_DIR = Path("./results")

ANALYSIS_DIR = Path("./data/zen3")
TABLE_DIR = ANALYSIS_DIR / "tables"
PLOT_DIR = ANALYSIS_DIR / "plots"
HISTOGRAM_DIR = Path("./data/histogram")

PMU_EVENTS_DIR = Path("./pmu-events/amdzen3")
AMDUPROF_PCM_EVENTS_FILE = Path("./pmu-events/zen3_amduprof_pcm_events.txt")

DEVICE = "/dev/tsa_bench"
TIMEOUT_S = 60.0 * 60 * 12 

OUT_PREFIX = "tsa_bench"

MAKE_TARGET_INSMOD_BMARKS = "insmod-bmarks"


BENCH_PLAN: Dict[int, List[str]] = {
    1: ["--repeats", "20"],
    2: ["--repeats", "20"],
    3: ["--repeats", "10"],
    4: ["--repeats", "10"],
    5: ["--mit-verw", "--mit-wbinvd", "--mit-l1d-flush", "--mit-cflush", "--repeats", "20"],
    9: ["--repeats", "20"],
    10: ["--event-range", "0x76:0x76", "--umask-range", "0x80:0x80", "--repeats", "100"],
}


MITIGATION_NAMES: Dict[int, str] = {
    1 << 0: "VERW",
    1 << 1: "WBINVD",
    1 << 2: "L1D_FLUSH",
    1 << 3: "CFLUSH",
}



def round_up_to_nearest_10(value: float) -> int:
    return int(math.ceil(value / 10.0) * 10)


def harmonic_mean_nonnegative(values: List[float]) -> float:
    """
    Harmonic mean for non-negative throughput/rate values.

    If any run has zero throughput, the harmonic mean is zero.
    Negative rates are ignored because they are invalid for this metric.
    """
    valid_values = [value for value in values if value >= 0.0]

    if not valid_values:
        return 0.0

    if any(value == 0.0 for value in valid_values):
        return 0.0

    return harmonic_mean(valid_values)


def population_variance(values: List[float]) -> float:
    if not values:
        return 0.0

    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def run_cmd(cmd: List[str], description: str) -> None:
    print()
    print("=" * 80)
    print(f"[+] {description}")
    print(f"[+] Command: {' '.join(cmd)}")
    print("=" * 80)
    print(flush=True)

    completed = subprocess.run(cmd)

    if completed.returncode != 0:
        raise RuntimeError(
            f"{description} failed with exit code {completed.returncode}"
        )


def load_benchmark_module() -> None:
    completed = subprocess.run(
        ["sudo", "make", MAKE_TARGET_INSMOD_BMARKS],
        capture_output=True,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"Loading benchmark kernel module failed with exit code {completed.returncode}"
        )

    print("[+] Module loaded")


def run_benchmark(bench: int, out_file: Path, extra_args: List[str]) -> None:
    cmd = [
        sys.executable,
        str(COLLECTOR),
        "--device",
        DEVICE,
        "--bench",
        str(bench),
        "--out",
        str(out_file),
        "--timeout",
        str(TIMEOUT_S),
        *extra_args,
    ]

    run_cmd(
        cmd,
        f"Running benchmark {bench}, output={out_file}",
    )


def parse_benchmark_ids(value: str) -> List[int]:
    selected: List[int] = []

    for part in value.split(","):
        part = part.strip()

        if not part:
            continue

        try:
            bench = int(part, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid benchmark id {part!r}; expected one of {sorted(BENCH_PLAN)}"
            ) from exc

        if bench not in BENCH_PLAN:
            raise argparse.ArgumentTypeError(
                f"invalid benchmark id {bench}; expected one of {sorted(BENCH_PLAN)}"
            )

        if bench not in selected:
            selected.append(bench)

    if not selected:
        raise argparse.ArgumentTypeError("expected at least one benchmark id")

    return selected


def run_all_benchmarks(selected_benchmarks: Optional[List[int]] = None) -> List[Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    load_benchmark_module()

    run_stamp = int(time.time())
    result_files: List[Path] = []
    bench_plan = (
        [(bench, BENCH_PLAN[bench]) for bench in selected_benchmarks]
        if selected_benchmarks is not None
        else list(BENCH_PLAN.items())
    )

    for bench, extra_args in bench_plan:
        out_file = RESULTS_DIR / f"{OUT_PREFIX}_{run_stamp}_bench{bench}.jsonl"

        run_benchmark(
            bench=bench,
            out_file=out_file,
            extra_args=extra_args,
        )

        result_files.append(out_file)

    return result_files


def configure_analysis_paths(target: str) -> None:
    global ANALYSIS_DIR, TABLE_DIR, PLOT_DIR, PMU_EVENTS_DIR, AMDUPROF_PCM_EVENTS_FILE

    ANALYSIS_DIR = Path("./data") / target
    TABLE_DIR = ANALYSIS_DIR / "tables"
    PLOT_DIR = ANALYSIS_DIR / "plots"
    PMU_EVENTS_DIR = Path("./pmu-events") / f"amd{target}"
    AMDUPROF_PCM_EVENTS_FILE = Path("./pmu-events") / f"{target}_amduprof_pcm_events.txt"


def find_benchmark_result_files(bench: int) -> List[Path]:
    """
    Only scan the result directory once and only keep files for the requested benchmark.

    Expected filename suffix:
        _bench<nr>.jsonl

    Example:
        tsa_bench_1779091237_bench1.jsonl
    """
    if not RESULTS_DIR.exists():
        return []

    simple_name = f"bench{bench}.jsonl"
    suffix = f"_bench{bench}.jsonl"
    result_files: List[Path] = []

    for path in RESULTS_DIR.iterdir():
        if not path.is_file():
            continue

        if path.name == simple_name or path.name.endswith(suffix):
            result_files.append(path)

    return result_files


def load_jsonl_results(result_files: List[Path]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for path in result_files:
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip().strip("\x00")

                if not line:
                    continue

                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"[!] Skipping invalid JSON in {path}:{line_no}: {exc}")
                    continue

                if isinstance(row, dict):
                    rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Accuracy-vs-samples benchmarks
# ---------------------------------------------------------------------------

def get_accuracy_vs_samples_rows(
    rows: List[Dict[str, Any]],
    bench: int,
    bench_name: str,
) -> List[Dict[str, Any]]:
    bench_rows: List[Dict[str, Any]] = []

    for row in rows:
        if row.get("kind") != "RESULT":
            continue

        if row.get("bench") != bench:
            continue

        if row.get("bench_name") != bench_name:
            continue

        if "samples" not in row:
            continue

        if "working_pmcs" not in row:
            continue

        if "accuracy_permille" not in row:
            continue

        if "end_to_end_bps_x1000" not in row:
            continue

        bench_rows.append(row)

    return bench_rows


def get_bench1_accuracy_vs_samples_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return get_accuracy_vs_samples_rows(
        rows=rows,
        bench=1,
        bench_name="accuracy_vs_samples",
    )


def get_bench9_4k_alias_stlf_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return get_accuracy_vs_samples_rows(
        rows=rows,
        bench=9,
        bench_name="accuracy_vs_samples_4k_alias_stlf",
    )


def summarize_bench1_by_sweep_samples(
    bench1_rows: List[Dict[str, Any]],
    bench: int = 1,
) -> List[Dict[str, Any]]:
    """
    Group benchmark 1 by sweep sample count.

    For each sweep count:
      - median working PMCs
      - minimum working PMCs
      - maximum working PMCs
      - variance of working PMCs
      - median accuracy
      - harmonic mean end-to-end extraction rate

    accuracy_permille is converted to percent.
    end_to_end_bps_x1000 is divided by 1000.0 before the harmonic mean.
    """
    grouped: Dict[int, List[Dict[str, Any]]] = {}

    for row in bench1_rows:
        samples = int(row["samples"])
        grouped.setdefault(samples, []).append(row)

    summary_rows: List[Dict[str, Any]] = []

    for samples, sample_rows in grouped.items():
        working_pmcs_values = [
            int(row["working_pmcs"])
            for row in sample_rows
        ]

        accuracy_values = [
            int(row["accuracy_permille"]) / 10.0
            for row in sample_rows
        ]

        end_to_end_bps_values = [
            int(row["end_to_end_bps_x1000"]) / 1000.0
            for row in sample_rows
        ]

        summary_rows.append(
            {
                "bench": bench,
                "samples": samples,
                "working_pmcs_median": median(working_pmcs_values),
                "working_pmcs_min": min(working_pmcs_values),
                "working_pmcs_max": max(working_pmcs_values),
                "working_pmcs_variance": population_variance(working_pmcs_values),
                "accuracy_percent": median(accuracy_values),
                "end_to_end_bps": harmonic_mean_nonnegative(end_to_end_bps_values),
            }
        )

    summary_rows.sort(key=lambda row: int(row["samples"]))
    return summary_rows


def write_bench1_sweep_table(
    summary_rows: List[Dict[str, Any]],
    filename: str = "bench1_sweep_samples_summary.csv",
) -> Path:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    out_path = TABLE_DIR / filename

    fieldnames = [
        "bench",
        "samples",
        "working_pmcs_median",
        "working_pmcs_min",
        "working_pmcs_max",
        "working_pmcs_variance",
        "accuracy_percent",
        "end_to_end_bps",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            writer.writerow(
                {
                    "bench": int(row["bench"]),
                    "samples": int(row["samples"]),
                    "working_pmcs_median": f"{row['working_pmcs_median']:.2f}",
                    "working_pmcs_min": int(row["working_pmcs_min"]),
                    "working_pmcs_max": int(row["working_pmcs_max"]),
                    "working_pmcs_variance": f"{row['working_pmcs_variance']:.2f}",
                    "accuracy_percent": f"{row['accuracy_percent']:.2f}",
                    "end_to_end_bps": f"{row['end_to_end_bps']:.2f}",
                }
            )

    return out_path


def print_bench1_sweep_table(
    summary_rows: List[Dict[str, Any]],
    title: str = "Benchmark 1: sweep samples summary",
) -> None:
    print()
    print(f"[+] {title}")
    print()
    print(
        f"{'samples':>8}  "
        f"{'pmcs_med':>10}  "
        f"{'pmcs_min':>10}  "
        f"{'pmcs_max':>10}  "
        f"{'pmcs_var':>12}  "
        f"{'accuracy_%':>10}  "
        f"{'end_to_end_bps':>16}"
    )
    print("-" * 90)

    for row in summary_rows:
        print(
            f"{int(row['samples']):>8}  "
            f"{row['working_pmcs_median']:>10.2f}  "
            f"{int(row['working_pmcs_min']):>10}  "
            f"{int(row['working_pmcs_max']):>10}  "
            f"{row['working_pmcs_variance']:>12.2f}  "
            f"{row['accuracy_percent']:>10.2f}  "
            f"{row['end_to_end_bps']:>16.2f}"
        )


def analyze_bench1_accuracy_vs_samples() -> None:
    result_files = find_benchmark_result_files(bench=1)

    if not result_files:
        print(f"[!] No benchmark 1 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench1_rows = get_bench1_accuracy_vs_samples_rows(rows)

    if not bench1_rows:
        print("[!] No benchmark 1 accuracy_vs_samples RESULT rows found.")
        return

    summary_rows = summarize_bench1_by_sweep_samples(bench1_rows)
    table_path = write_bench1_sweep_table(summary_rows)

    print_bench1_sweep_table(summary_rows)

    print()
    print(f"[+] Bench 1 input files: {len(result_files)}")
    print(f"[+] Bench 1 input rows:  {len(bench1_rows)}")
    print(f"[+] Wrote table:        {table_path}")


def analyze_bench9_4k_alias_stlf_accuracy_vs_samples() -> None:
    result_files = find_benchmark_result_files(bench=9)

    if not result_files:
        print(f"[!] No benchmark 9 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench9_rows = get_bench9_4k_alias_stlf_rows(rows)

    if not bench9_rows:
        print("[!] No benchmark 9 accuracy_vs_samples_4k_alias_stlf RESULT rows found.")
        return

    summary_rows = summarize_bench1_by_sweep_samples(bench9_rows, bench=9)
    table_path = write_bench1_sweep_table(
        summary_rows,
        filename="bench9_4k_alias_stlf_sweep_samples_summary.csv",
    )

    print_bench1_sweep_table(
        summary_rows,
        title="Benchmark 9: 4K alias STLF sweep samples summary",
    )

    print()
    print(f"[+] Bench 9 input files: {len(result_files)}")
    print(f"[+] Bench 9 input rows:  {len(bench9_rows)}")
    print(f"[+] Wrote table:        {table_path}")


# ---------------------------------------------------------------------------
# Benchmark 10: scaled 1 GiB leak rate
# ---------------------------------------------------------------------------

def get_bench10_scaled_leak_rate_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    bench10_rows: List[Dict[str, Any]] = []

    for row in rows:
        if row.get("kind") != "RESULT":
            continue

        if row.get("bench") != 10:
            continue

        if row.get("bench_name") != "scaled_1gib_leak_rate":
            continue

        if "event" not in row:
            continue

        if "umask" not in row:
            continue

        if "samples" not in row:
            continue

        if "accuracy_permille" not in row and ("correct" not in row or "total" not in row):
            continue

        if "raw_bps_x1000" not in row and ("total" not in row or "ext_ns" not in row):
            continue

        bench10_rows.append(row)

    return bench10_rows


def bench10_accuracy_percent(row: Dict[str, Any]) -> float:
    if "accuracy_permille" in row:
        return int(row["accuracy_permille"]) / 10.0

    total = int(row.get("total", 0))
    if total <= 0:
        return 0.0

    return int(row.get("correct", 0)) * 100.0 / total


def bench10_extraction_rate_bps(row: Dict[str, Any]) -> float:
    if "raw_bps_x1000" in row:
        return int(row["raw_bps_x1000"]) / 1000.0

    total = int(row.get("total", 0))
    ext_ns = int(row.get("ext_ns", 0))

    if total <= 0 or ext_ns <= 0:
        return 0.0

    return total * 1_000_000_000.0 / ext_ns


def summarize_bench10_by_event_umask_samples(
    bench10_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[int, int, int], List[Dict[str, Any]]] = {}

    for row in bench10_rows:
        event = int(row["event"])
        umask = int(row["umask"])
        samples = int(row["samples"])
        grouped.setdefault((event, umask, samples), []).append(row)

    summary_rows: List[Dict[str, Any]] = []

    for (event, umask, samples), group_rows in grouped.items():
        accuracy_values = [
            bench10_accuracy_percent(row)
            for row in group_rows
        ]
        extraction_rate_values = [
            bench10_extraction_rate_bps(row)
            for row in group_rows
        ]

        summary_rows.append(
            {
                "bench": 10,
                "event": event,
                "umask": umask,
                "samples": samples,
                "runs": len(group_rows),
                "accuracy_percent_avg": sum(accuracy_values) / len(accuracy_values),
                "accuracy_percent_variance": population_variance(accuracy_values),
                "extraction_rate_bps_avg": sum(extraction_rate_values) / len(extraction_rate_values),
                "extraction_rate_bps_variance": population_variance(extraction_rate_values),
            }
        )

    summary_rows.sort(
        key=lambda row: (
            int(row["event"]),
            int(row["umask"]),
            int(row["samples"]),
        )
    )
    return summary_rows


def write_bench10_scaled_leak_rate_table(
    summary_rows: List[Dict[str, Any]],
) -> Path:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    out_path = TABLE_DIR / "bench10_scaled_1gib_leak_rate.csv"

    fieldnames = [
        "bench",
        "event",
        "umask",
        "samples",
        "runs",
        "accuracy_percent_avg",
        "accuracy_percent_variance",
        "extraction_rate_bps_avg",
        "extraction_rate_bps_variance",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            writer.writerow(
                {
                    "bench": int(row["bench"]),
                    "event": f"0x{int(row['event']):02x}",
                    "umask": f"0x{int(row['umask']):02x}",
                    "samples": int(row["samples"]),
                    "runs": int(row["runs"]),
                    "accuracy_percent_avg": f"{row['accuracy_percent_avg']:.2f}",
                    "accuracy_percent_variance": f"{row['accuracy_percent_variance']:.2f}",
                    "extraction_rate_bps_avg": f"{row['extraction_rate_bps_avg']:.2f}",
                    "extraction_rate_bps_variance": f"{row['extraction_rate_bps_variance']:.2f}",
                }
            )

    return out_path


def print_bench10_scaled_leak_rate_table(
    summary_rows: List[Dict[str, Any]],
) -> None:
    print()
    print("[+] Benchmark 10: scaled 1 GiB leak rate")
    print()
    print(
        f"{'event':>8}  "
        f"{'umask':>8}  "
        f"{'samples':>8}  "
        f"{'runs':>6}  "
        f"{'accuracy_avg_%':>14}  "
        f"{'acc_var':>10}  "
        f"{'extraction_bps_avg':>20}  "
        f"{'rate_var':>16}"
    )
    print("-" * 110)

    for row in summary_rows:
        print(
            f"{'0x' + format(int(row['event']), '02x'):>8}  "
            f"{'0x' + format(int(row['umask']), '02x'):>8}  "
            f"{int(row['samples']):>8}  "
            f"{int(row['runs']):>6}  "
            f"{row['accuracy_percent_avg']:>14.2f}  "
            f"{row['accuracy_percent_variance']:>10.2f}  "
            f"{row['extraction_rate_bps_avg']:>20.2f}  "
            f"{row['extraction_rate_bps_variance']:>16.2f}"
        )


def analyze_bench10_scaled_1gib_leak_rate() -> None:
    result_files = find_benchmark_result_files(bench=10)

    if not result_files:
        print(f"[!] No benchmark 10 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench10_rows = get_bench10_scaled_leak_rate_rows(rows)

    if not bench10_rows:
        print("[!] No benchmark 10 scaled_1gib_leak_rate RESULT rows found.")
        return

    summary_rows = summarize_bench10_by_event_umask_samples(bench10_rows)
    table_path = write_bench10_scaled_leak_rate_table(summary_rows)

    print_bench10_scaled_leak_rate_table(summary_rows)

    print()
    print(f"[+] Bench 10 input files: {len(result_files)}")
    print(f"[+] Bench 10 input rows:  {len(bench10_rows)}")
    print(f"[+] Wrote table:         {table_path}")


# ---------------------------------------------------------------------------
# Benchmark 2: secret_length_scaling
# ---------------------------------------------------------------------------

def get_bench2_secret_length_scaling_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    bench2_rows: List[Dict[str, Any]] = []

    for row in rows:
        if row.get("kind") != "RESULT":
            continue

        if row.get("bench") != 2:
            continue

        if row.get("bench_name") != "secret_length_scaling":
            continue

        if "secret_bits" not in row:
            continue

        if "accuracy_permille" not in row:
            continue

        if "end_to_end_bps_x1000" not in row:
            continue

        bench2_rows.append(row)

    return bench2_rows


def summarize_bench2_by_secret_bits(
    bench2_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Group benchmark 2 rows by secret_bits.

    Accuracy is converted from permille to percent and summarized by median.
    end_to_end_bps_x1000 is divided by 1000.0 and summarized by harmonic mean.
    """
    grouped: Dict[int, List[Dict[str, Any]]] = {}

    for row in bench2_rows:
        secret_bits = int(row["secret_bits"])
        grouped.setdefault(secret_bits, []).append(row)

    summary_rows: List[Dict[str, Any]] = []

    for secret_bits, secret_rows in grouped.items():
        accuracy_values = [
            int(row["accuracy_permille"]) / 10.0
            for row in secret_rows
        ]

        end_to_end_bps_values = [
            int(row["end_to_end_bps_x1000"]) / 1000.0
            for row in secret_rows
        ]

        summary_rows.append(
            {
                "bench": 2,
                "secret_bits": secret_bits,
                "accuracy_percent": median(accuracy_values),
                "end_to_end_bps": harmonic_mean_nonnegative(end_to_end_bps_values),
            }
        )

    summary_rows.sort(key=lambda row: int(row["secret_bits"]))
    return summary_rows


def write_bench2_secret_length_table(summary_rows: List[Dict[str, Any]]) -> Path:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    out_path = TABLE_DIR / "bench2_secret_length_scaling.csv"

    fieldnames = [
        "bench",
        "secret_bits",
        "accuracy_percent",
        "end_to_end_bps",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            writer.writerow(
                {
                    "bench": int(row["bench"]),
                    "secret_bits": int(row["secret_bits"]),
                    "accuracy_percent": f"{row['accuracy_percent']:.2f}",
                    "end_to_end_bps": f"{row['end_to_end_bps']:.2f}",
                }
            )

    return out_path


def print_bench2_secret_length_table(summary_rows: List[Dict[str, Any]]) -> None:
    print()
    print("[+] Benchmark 2: secret length scaling")
    print()
    print(
        f"{'secret_bits':>12}  "
        f"{'accuracy_%':>10}  "
        f"{'end_to_end_bps':>16}"
    )
    print("-" * 42)

    for row in summary_rows:
        print(
            f"{int(row['secret_bits']):>12}  "
            f"{row['accuracy_percent']:>10.2f}  "
            f"{row['end_to_end_bps']:>16.2f}"
        )


def analyze_bench2_secret_length_scaling() -> None:
    result_files = find_benchmark_result_files(bench=2)

    if not result_files:
        print(f"[!] No benchmark 2 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench2_rows = get_bench2_secret_length_scaling_rows(rows)

    if not bench2_rows:
        print("[!] No benchmark 2 secret_length_scaling RESULT rows found.")
        return

    summary_rows = summarize_bench2_by_secret_bits(bench2_rows)
    table_path = write_bench2_secret_length_table(summary_rows)

    print_bench2_secret_length_table(summary_rows)

    print()
    print(f"[+] Bench 2 input files: {len(result_files)}")
    print(f"[+] Bench 2 input rows:  {len(bench2_rows)}")
    print(f"[+] Wrote table:        {table_path}")


# ---------------------------------------------------------------------------
# PMU event helpers for benchmarks 3 and 4
# ---------------------------------------------------------------------------

def parse_int_values(value: Any) -> Set[int]:
    """
    Parse integer values from perf PMU JSON fields.

    Handles values like:
      0x76
      76
      0x01,0x02
      0x01 | 0x02
    """
    if value is None:
        return set()

    if isinstance(value, int):
        return {value}

    text = str(value)
    numbers: Set[int] = set()

    for token in re.findall(r"0x[0-9a-fA-F]+|\d+", text):
        try:
            if token.lower().startswith("0x"):
                numbers.add(int(token, 16))
            else:
                numbers.add(int(token, 10))
        except ValueError:
            continue

    return numbers


def normalise_category_from_file(path: Path) -> str:
    return path.stem.replace("_", "-").lower()


def iter_perf_event_entries(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]

    if isinstance(data, dict):
        for key in ("Events", "events"):
            value = data.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]

    return []


def get_umask_values(entry: Dict[str, Any]) -> Set[int]:
    for key in ("UMask", "UnitMask", "Umask", "umask", "Unitmask"):
        if key in entry:
            return parse_int_values(entry.get(key))

    return set()


def load_pmu_event_index() -> Tuple[
    Dict[int, List[Dict[str, Any]]],
    Dict[Tuple[int, int], List[Dict[str, Any]]],
]:
    """
    Load perf PMU event descriptions from PMU_EVENTS_DIR.

    Uses full EventCode matching. No low-byte truncation.
    """
    event_index: Dict[int, List[Dict[str, Any]]] = {}
    event_umask_index: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}

    if not PMU_EVENTS_DIR.exists():
        print(f"[!] PMU events directory does not exist: {PMU_EVENTS_DIR}")
        return event_index, event_umask_index

    for path in PMU_EVENTS_DIR.rglob("*.json"):
        category = normalise_category_from_file(path)

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            print(f"[!] Skipping invalid PMU JSON {path}: {exc}")
            continue

        entries = iter_perf_event_entries(data)

        for entry in entries:
            event_codes = parse_int_values(entry.get("EventCode"))

            if not event_codes:
                continue

            umasks = get_umask_values(entry)

            for event_code in event_codes:
                indexed_entry = {
                    "category": category,
                    "event_code": event_code,
                    "umasks": sorted(umasks),
                    "event_name": str(entry.get("EventName", "")),
                    "brief_description": str(entry.get("BriefDescription", "")),
                    "source_file": str(path),
                }

                event_index.setdefault(event_code, []).append(indexed_entry)

                for umask in umasks:
                    event_umask_index.setdefault(
                        (event_code, umask),
                        [],
                    ).append(indexed_entry)

    return event_index, event_umask_index


def get_best_pmu_description(
    event: int,
    umask: int,
    event_index: Dict[int, List[Dict[str, Any]]],
    event_umask_index: Dict[Tuple[int, int], List[Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    """
    Prefer exact EventCode + UMask match.

    If no UMask match exists but EventCode exists, still return an event-level
    description. That row will be emitted without umask information.
    """
    exact_matches = event_umask_index.get((event, umask))

    if exact_matches:
        match = dict(exact_matches[0])
        match["match_type"] = "event+umask"
        return match

    event_matches = event_index.get(event)

    if not event_matches:
        return None

    no_umask_matches = [
        match
        for match in event_matches
        if not match.get("umasks")
    ]

    if no_umask_matches:
        match = dict(no_umask_matches[0])
        match["match_type"] = "event"
        return match

    match = dict(event_matches[0])
    match["match_type"] = "event"
    return match


def unique_working_pmcs(
    bench_rows: List[Dict[str, Any]],
) -> List[Tuple[int, int]]:
    pmcs: Set[Tuple[int, int]] = set()

    for row in bench_rows:
        event = int(row["event"])
        umask = int(row["umask"])
        pmcs.add((event, umask))

    return sorted(pmcs)


def categorize_pmc_by_event_code(
    event: int,
    event_index: Dict[int, List[Dict[str, Any]]],
) -> str:
    matches = event_index.get(event)

    if not matches:
        return "undocumented"

    return str(matches[0]["category"])


def summarize_working_pmc_categories(
    working_pmcs: List[Tuple[int, int]],
    event_index: Dict[int, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}

    for event, _umask in working_pmcs:
        category = categorize_pmc_by_event_code(event, event_index)
        counts[category] = counts.get(category, 0) + 1

    summary_rows = [
        {
            "category": category,
            "amount": amount,
        }
        for category, amount in counts.items()
    ]

    summary_rows.sort(
        key=lambda row: (
            -int(row["amount"]),
            str(row["category"]),
        )
    )

    return summary_rows


def write_pmc_category_table(
    summary_rows: List[Dict[str, Any]],
    out_path: Path,
) -> Path:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "category",
        "amount",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            writer.writerow(
                {
                    "category": str(row["category"]),
                    "amount": int(row["amount"]),
                }
            )

    return out_path


def short_pmu_description_title(description: Dict[str, Any]) -> str:
    """Return a compact event-level description for the detail CSV."""
    brief_description = str(description.get("brief_description", "")).strip()

    if brief_description:
        return brief_description.split(".", 1)[0].strip()

    event_name = str(description.get("event_name", "")).strip()

    if event_name:
        return event_name

    return "undocumented"


def summarize_working_pmc_events(
    working_pmcs: List[Tuple[int, int]],
    event_index: Dict[int, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """
    Summarize unique working PMCs at EventCode granularity.

    The count is the number of unique working PMC configurations with this
    EventCode. A PMC configuration is still de-duplicated as (event, umask),
    so repeated runs of the same EventCode + UMask only count once.

    UMask values are intentionally not emitted in this table.
    """
    unique_pmcs_by_event: Dict[int, Set[Tuple[int, int]]] = {}

    for event, umask in working_pmcs:
        unique_pmcs_by_event.setdefault(event, set()).add((event, umask))

    rows: List[Dict[str, Any]] = []

    for event, unique_pmcs in unique_pmcs_by_event.items():
        descriptions = event_index.get(event)

        if not descriptions:
            continue

        # Prefer a generic event-level description if present. Otherwise use
        # the most common title extracted from the BriefDescription. This avoids
        # expanding the table back into UMask-level aliases such as
        # ic_fetch_stall.ic_stall_any.
        generic_descriptions = [
            description
            for description in descriptions
            if not description.get("umasks")
        ]
        candidate_descriptions = generic_descriptions or descriptions

        description_titles = [
            short_pmu_description_title(description)
            for description in candidate_descriptions
        ]
        title_counts = Counter(description_titles)
        description_title = title_counts.most_common(1)[0][0]
        description = candidate_descriptions[0]

        rows.append(
            {
                "category": str(description["category"]),
                "event_code": f"0x{event:x}",
                "description": description_title,
                "count": len(unique_pmcs),
            }
        )

    rows.sort(
        key=lambda row: (
            str(row["category"]),
            int(str(row["event_code"]), 16),
            str(row["description"]),
        )
    )

    return rows


def write_pmc_detail_table(
    working_pmcs: List[Tuple[int, int]],
    event_index: Dict[int, List[Dict[str, Any]]],
    out_path: Path,
) -> Path:
    """
    Detailed event-level table for benchmarks 3 and 4.

    Output columns:
        category,event_code,description,count

    The count is the number of unique working PMC configurations with the
    matching EventCode. Repeated runs of the same EventCode + UMask are
    counted once. UMask values are not written.
    """
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "category",
        "event_code",
        "description",
        "count",
    ]

    rows = summarize_working_pmc_events(
        working_pmcs=working_pmcs,
        event_index=event_index,
    )

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow(row)

    return out_path


def extract_threshold_values(
    bench_rows: List[Dict[str, Any]],
) -> List[int]:
    """
    Extract threshold values for histogramming.

    The benchmark rows contain one threshold per working PMC result. This is
    the only value used for the histogram output.
    """
    values: List[int] = []

    for row in bench_rows:
        value = row.get("threshold")

        if isinstance(value, bool):
            continue

        if isinstance(value, int):
            values.append(value)
            continue

        if isinstance(value, float) and value.is_integer():
            values.append(int(value))
            continue

        if isinstance(value, str):
            text = value.strip()
            if not text:
                continue

            try:
                values.append(int(text, 0))
            except ValueError:
                continue

    return values


def write_threshold_histogram_pdf(
    bench_rows: List[Dict[str, Any]],
    bench_label: str,
    out_path: Path,
) -> Optional[Path]:
    """
    Write exactly one threshold histogram PDF for one benchmark.

    No histogram CSVs are written and no other numeric fields are plotted.
    """
    values = extract_unique_pmc_threshold_values(bench_rows)

    if not values:
        print(f"[!] No threshold values found for {bench_label}")
        return None

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib is not installed, skipping threshold histogram PDF")
        return None

    PLOT_DIR.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(10, 5))

    unique_count = len(set(values))
    if unique_count <= 128:
        counts = Counter(values)
        xs = sorted(counts)
        ys = [counts[x] for x in xs]
        plt.bar(xs, ys)
        plt.ylabel("duplicate count")
    else:
        bins = min(
            128,
            max(10, round_up_to_nearest_10(math.sqrt(len(values)))),
        )
        plt.hist(values, bins=bins)
        plt.ylabel("count")

    plt.xlabel("threshold")
    plt.title(f"{bench_label}: threshold histogram")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

    return out_path


def threshold_histogram_csv_path(target: str) -> Path:
    return HISTOGRAM_DIR / f"bench3_{target}_threshold_histogram.csv"


def write_threshold_histogram_csv(
    values: List[int],
    target: str,
    out_path: Path,
) -> Optional[Path]:
    if not values:
        print(f"[!] No threshold values found for bench3 {target} histogram CSV")
        return None

    HISTOGRAM_DIR.mkdir(parents=True, exist_ok=True)

    counts = Counter(values)
    fieldnames = ["target", "threshold", "count"]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for threshold in sorted(counts):
            writer.writerow(
                {
                    "target": target,
                    "threshold": threshold,
                    "count": counts[threshold],
                }
            )

    return out_path

def extract_unique_pmc_threshold_values(
    bench_rows: List[Dict[str, Any]],
) -> List[int]:
    """
    Extract one threshold value per unique working PMC configuration.

    A PMC configuration is identified by (event, umask). If the same
    configuration appears multiple times across runs or files, its threshold
    values are collapsed to one representative value using the median.

    This prevents repeated benchmark runs from inflating the histogram.
    """
    thresholds_by_pmc: Dict[Tuple[int, int], List[int]] = {}

    for row in bench_rows:
        if "event" not in row or "umask" not in row:
            continue

        value = row.get("threshold")

        if isinstance(value, bool):
            continue

        threshold: Optional[int] = None

        if isinstance(value, int):
            threshold = value
        elif isinstance(value, float) and value.is_integer():
            threshold = int(value)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                continue

            try:
                threshold = int(text, 0)
            except ValueError:
                continue

        if threshold is None:
            continue

        event = int(row["event"])
        umask = int(row["umask"])
        thresholds_by_pmc.setdefault((event, umask), []).append(threshold)

    values: List[int] = []

    for thresholds in thresholds_by_pmc.values():
        values.append(int(round(median(thresholds))))

    return values


def ensure_bench3_threshold_histogram_csv(
    bench_rows: List[Dict[str, Any]],
    target: str,
) -> Optional[Path]:
    out_path = threshold_histogram_csv_path(target)

    if out_path.exists():
        print(f"[+] Reusing cached bench 3 histogram CSV: {out_path}")
        return out_path

    values = extract_unique_pmc_threshold_values(bench_rows)
    return write_threshold_histogram_csv(
        values=values,
        target=target,
        out_path=out_path,
    )


def load_threshold_histogram_csv(path: Path) -> Tuple[str, Dict[int, int]]:
    target = path.stem
    prefix = "bench3_"
    suffix = "_threshold_histogram"

    if target.startswith(prefix) and target.endswith(suffix):
        target = target[len(prefix) : -len(suffix)]

    counts: Dict[int, int] = {}

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            row_target = row.get("target")
            if row_target:
                target = row_target

            try:
                threshold = int(str(row["threshold"]), 0)
                count = int(str(row["count"]), 0)
            except (KeyError, TypeError, ValueError):
                continue

            counts[threshold] = counts.get(threshold, 0) + count

    return target, counts



def write_merged_bench3_threshold_histogram_pdf() -> Optional[Path]:
    """
    Write one merged bench 3 threshold bar plot from cached per-target CSVs.
    """
    HISTOGRAM_DIR.mkdir(parents=True, exist_ok=True)

    current_target = ANALYSIS_DIR.name
    current_csv_path = threshold_histogram_csv_path(current_target)

    if not current_csv_path.exists():
        result_files = find_benchmark_result_files(bench=3)

        if not result_files:
            print(f"[!] No benchmark 3 JSONL files found in {RESULTS_DIR}")
        else:
            rows = load_jsonl_results(result_files)
            bench3_rows = get_bench3_working_pmc_rows(rows)

            if not bench3_rows:
                print("[!] No working benchmark 3 RESULT rows found.")
            else:
                created_csv_path = ensure_bench3_threshold_histogram_csv(
                    bench_rows=bench3_rows,
                    target=current_target,
                )

                if created_csv_path is not None:
                    print(f"[+] Bench 3 histogram CSV: {created_csv_path}")

    csv_paths = sorted(HISTOGRAM_DIR.glob("bench3_*_threshold_histogram.csv"))

    if not csv_paths:
        print(f"[!] No bench 3 histogram CSVs found in {HISTOGRAM_DIR}")
        return None

    histograms: List[Tuple[str, Dict[int, int]]] = []

    for csv_path in csv_paths:
        target, counts = load_threshold_histogram_csv(csv_path)
        duplicate_counts = {
            threshold: count
            for threshold, count in counts.items()
            if count >= 2
        }

        if not duplicate_counts:
            continue

        histograms.append((target, duplicate_counts))

    if not histograms:
        print(f"[!] No duplicate threshold values found in {HISTOGRAM_DIR}")
        return None

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib is not installed, skipping merged threshold histogram PDF")
        return None

    out_path = HISTOGRAM_DIR / "bench3_threshold_histograms_merged.pdf"

    colors = [
        "#A03232", "#2D2DB9", "#595959", "#1B9E77", "#D95F02",
        "#7570B3", "#66A61E", "#E6AB02", "#A6761D", "#666666",
        "#FF7F0E", "#1F77B4", "#2CA02C", "#9467BD", "#8C564B",
    ]

    plt.rcParams["font.family"] = "DejaVu Sans"
    plt.figure(figsize=(10, 5))

    ax = plt.gca()
    ax.set_facecolor("#f5f5f5")

    all_thresholds = sorted(
        {
            threshold
            for _target, counts in histograms
            for threshold in counts
        }
    )
    max_exact_threshold_bars = 64
    max_bucket_bars = 20

    if len(all_thresholds) <= max_exact_threshold_bars:
        bucket_width = 1
    else:
        threshold_range = all_thresholds[-1] - all_thresholds[0] + 1
        bucket_width = max(1, math.ceil(threshold_range / max_bucket_bars))

        if bucket_width > 10:
            bucket_width = round_up_to_nearest_10(bucket_width)

    min_threshold = all_thresholds[0]

    def threshold_bucket_start(threshold: int) -> int:
        return min_threshold + ((threshold - min_threshold) // bucket_width) * bucket_width

    bucket_starts = sorted(
        {
            threshold_bucket_start(threshold)
            for threshold in all_thresholds
        }
    )
    x_positions = list(range(len(bucket_starts)))
    n_histograms = len(histograms)
    bar_width = 0.8 / max(n_histograms, 1)

    label_map = {
        'zen3': 'AMD Zen 3',
        'zen4': 'AMD Zen 4',
    }

    for i, (target, counts) in enumerate(histograms):
        offset = -0.4 + bar_width / 2 + i * bar_width
        xs = [x + offset for x in x_positions]
        bucket_counts: Counter[int] = Counter()

        for threshold, count in counts.items():
            bucket_start = threshold_bucket_start(threshold)
            bucket_counts[bucket_start] += count

        ys = [bucket_counts.get(bucket_start, 0) for bucket_start in bucket_starts]

        plt.bar(
            xs,
            ys,
            width=bar_width * 0.92,
            color=colors[i % len(colors)],
            label=label_map.get(target, target),
            edgecolor="none",
        )

    plt.ylabel("Duplicate Count")
    plt.yscale("log")

    def format_bucket_label(bucket_start: int) -> str:
        if bucket_width <= 60:
            return str(bucket_start)

        return f"[{bucket_start}, {bucket_start + bucket_width})"

    if len(bucket_starts) <= 64:
        tick_positions = x_positions
        tick_labels = [
            format_bucket_label(bucket_start)
            for bucket_start in bucket_starts
        ]
    else:
        tick_step = max(1, math.ceil(len(bucket_starts) / 32))
        tick_positions = x_positions[::tick_step]
        tick_labels = [
            format_bucket_label(bucket_start)
            for bucket_start in bucket_starts[::tick_step]
        ]

        if tick_positions[-1] != x_positions[-1]:
            tick_positions.append(x_positions[-1])
            last_bucket_start = bucket_starts[-1]
            tick_labels.append(format_bucket_label(last_bucket_start))

    plt.xticks(tick_positions, tick_labels, rotation=45, ha="right")

    plt.xlabel("Otsu's Threshold")
    plt.grid(True, linestyle="--", alpha=0.6)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)

    ax.set_ylabel(ax.get_ylabel(), rotation=0, labelpad=40, ha="left")
    ax.yaxis.set_label_coords(0, 1.02)

    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, bbox_inches="tight", dpi=300)
    plt.close()

    return out_path


def print_category_table(title: str, summary_rows: List[Dict[str, Any]]) -> None:
    print()
    print(title)
    print()
    print(
        f"{'category':<32}  "
        f"{'amount':>8}"
    )
    print("-" * 42)

    for row in summary_rows:
        print(
            f"{str(row['category']):<32}  "
            f"{int(row['amount']):>8}"
        )


# ---------------------------------------------------------------------------
# Benchmark 3: working PMCs
# ---------------------------------------------------------------------------

def get_bench3_working_pmc_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    bench3_rows: List[Dict[str, Any]] = []

    for row in rows:
        if row.get("kind") != "RESULT":
            continue

        if row.get("bench") != 3:
            continue

        if row.get("bench_name") != "working_pmcs":
            continue

        if "event" not in row:
            continue

        if "umask" not in row:
            continue

        if int(row.get("working", 0)) == 0:
            continue

        bench3_rows.append(row)

    return bench3_rows


def analyze_bench3_working_pmc_categories() -> None:
    result_files = find_benchmark_result_files(bench=3)

    if not result_files:
        print(f"[!] No benchmark 3 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench3_rows = get_bench3_working_pmc_rows(rows)

    if not bench3_rows:
        print("[!] No working benchmark 3 RESULT rows found.")
        return

    working_pmcs = unique_working_pmcs(bench3_rows)

    event_index, event_umask_index = load_pmu_event_index()

    summary_rows = summarize_working_pmc_categories(
        working_pmcs=working_pmcs,
        event_index=event_index,
    )

    category_table_path = write_pmc_category_table(
        summary_rows=summary_rows,
        out_path=TABLE_DIR / "bench3_working_pmc_categories.csv",
    )

    detail_table_path = write_pmc_detail_table(
        working_pmcs=working_pmcs,
        event_index=event_index,
        out_path=TABLE_DIR / "bench3_working_pmc_details.csv",
    )

    threshold_histogram_path = write_threshold_histogram_pdf(
        bench_rows=bench3_rows,
        bench_label="bench3_working_pmcs",
        out_path=PLOT_DIR / "bench3_working_pmcs_threshold_histogram.pdf",
    )

    print_category_table(
        title="[+] Benchmark 3: working PMC categories",
        summary_rows=summary_rows,
    )

    print()
    print(f"[+] Bench 3 input files:       {len(result_files)}")
    print(f"[+] Bench 3 working rows:      {len(bench3_rows)}")
    print(f"[+] Bench 3 unique PMCs:       {len(working_pmcs)}")
    print(f"[+] PMU event categories from: {PMU_EVENTS_DIR}")
    print(f"[+] Wrote category table:      {category_table_path}")
    print(f"[+] Wrote detail table:        {detail_table_path}")
    if threshold_histogram_path is not None:
        print(f"[+] Wrote threshold histogram: {threshold_histogram_path}")


# ---------------------------------------------------------------------------
# Benchmark 4: physical access working PMCs
# ---------------------------------------------------------------------------

def get_bench4_working_pmc_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    bench4_rows: List[Dict[str, Any]] = []

    for row in rows:
        if row.get("kind") != "RESULT":
            continue

        if row.get("bench") != 4:
            continue

        if row.get("bench_name") != "virtual_vs_physical":
            continue

        if "event" not in row:
            continue

        if "umask" not in row:
            continue

        if int(row.get("working", 0)) == 0:
            continue

        bench4_rows.append(row)

    return bench4_rows


def analyze_bench4_physical_access_working_pmc_categories() -> None:
    result_files = find_benchmark_result_files(bench=4)

    if not result_files:
        print(f"[!] No benchmark 4 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench4_rows = get_bench4_working_pmc_rows(rows)

    if not bench4_rows:
        print("[!] No working benchmark 4 RESULT rows found.")
        return

    working_pmcs = unique_working_pmcs(bench4_rows)

    event_index, event_umask_index = load_pmu_event_index()

    summary_rows = summarize_working_pmc_categories(
        working_pmcs=working_pmcs,
        event_index=event_index,
    )

    category_table_path = write_pmc_category_table(
        summary_rows=summary_rows,
        out_path=TABLE_DIR / "bench4_physical_access_working_pmc_categories.csv",
    )

    detail_table_path = write_pmc_detail_table(
        working_pmcs=working_pmcs,
        event_index=event_index,
        out_path=TABLE_DIR / "bench4_physical_access_working_pmc_details.csv",
    )

    threshold_histogram_path = write_threshold_histogram_pdf(
        bench_rows=bench4_rows,
        bench_label="bench4_physical_access_working_pmcs",
        out_path=PLOT_DIR / "bench4_physical_access_working_pmcs_threshold_histogram.pdf",
    )

    print_category_table(
        title="[+] Benchmark 4: physical-access working PMC categories",
        summary_rows=summary_rows,
    )

    print()
    print(f"[+] Bench 4 input files:       {len(result_files)}")
    print(f"[+] Bench 4 working rows:      {len(bench4_rows)}")
    print(f"[+] Bench 4 unique PMCs:       {len(working_pmcs)}")
    print(f"[+] PMU event categories from: {PMU_EVENTS_DIR}")
    print(f"[+] Wrote category table:      {category_table_path}")
    print(f"[+] Wrote detail table:        {detail_table_path}")
    if threshold_histogram_path is not None:
        print(f"[+] Wrote threshold histogram: {threshold_histogram_path}")


# ---------------------------------------------------------------------------
# AMD uProf event-count analysis for benchmarks 3 and 4
# ---------------------------------------------------------------------------

def load_amduprof_pcm_event_names() -> Dict[int, str]:
    """
    Parse pmu-events/amduprof_pcm_events.txt.

    Expected lines:
        PMCx003      Retired SSE/AVX FLOPs
        PMCx18E      IC Tag Hit/Miss Events

    Returns:
        event_code -> name
    """
    event_names: Dict[int, str] = {}

    if not AMDUPROF_PCM_EVENTS_FILE.exists():
        print(f"[!] AMD uProf PMC event file does not exist: {AMDUPROF_PCM_EVENTS_FILE}")
        return event_names

    line_re = re.compile(r"^\s*PMCx([0-9a-fA-F]+)\s+(.+?)\s*$")

    with AMDUPROF_PCM_EVENTS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            match = line_re.match(line)

            if not match:
                continue

            event_code = int(match.group(1), 16)
            event_name = match.group(2).strip()

            event_names[event_code] = event_name

    return event_names


def summarize_amduprof_event_counts(
    working_pmcs: List[Tuple[int, int]],
    event_names: Dict[int, str],
) -> List[Dict[str, Any]]:
    """
    Count working PMCs by EventCode using the AMD uProf event-name file.

    Output:
        pmc, name, count

    If EventCode is not in the AMD uProf file, aggregate into:
        undocumented, undocumented, count
    """
    counts: Dict[int, int] = {}
    undocumented_count = 0

    for event, _umask in working_pmcs:
        if event not in event_names:
            undocumented_count += 1
            continue

        counts[event] = counts.get(event, 0) + 1

    summary_rows: List[Dict[str, Any]] = []

    for event, count in counts.items():
        summary_rows.append(
            {
                "pmc": f"PMCx{event:03X}",
                "name": event_names[event],
                "count": count,
            }
        )

    if undocumented_count > 0:
        summary_rows.append(
            {
                "pmc": "undocumented",
                "name": "undocumented",
                "count": undocumented_count,
            }
        )

    summary_rows.sort(
        key=lambda row: (
            str(row["pmc"]) == "undocumented",
            -int(row["count"]),
            str(row["pmc"]),
        )
    )

    return summary_rows


def write_amduprof_event_count_table(
    summary_rows: List[Dict[str, Any]],
    out_path: Path,
) -> Path:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "pmc",
        "name",
        "count",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            writer.writerow(
                {
                    "pmc": str(row["pmc"]),
                    "name": str(row["name"]),
                    "count": int(row["count"]),
                }
            )

    return out_path


def print_amduprof_event_count_table(
    title: str,
    summary_rows: List[Dict[str, Any]],
) -> None:
    print()
    print(title)
    print()
    print(
        f"{'pmc':<16}  "
        f"{'count':>8}  "
        f"{'name'}"
    )
    print("-" * 80)

    for row in summary_rows:
        print(
            f"{str(row['pmc']):<16}  "
            f"{int(row['count']):>8}  "
            f"{str(row['name'])}"
        )


def analyze_bench3_amduprof_pcm_events() -> None:
    result_files = find_benchmark_result_files(bench=3)

    if not result_files:
        print(f"[!] No benchmark 3 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench3_rows = get_bench3_working_pmc_rows(rows)

    if not bench3_rows:
        print("[!] No working benchmark 3 RESULT rows found for AMD uProf event analysis.")
        return

    working_pmcs = unique_working_pmcs(bench3_rows)
    event_names = load_amduprof_pcm_event_names()

    summary_rows = summarize_amduprof_event_counts(
        working_pmcs=working_pmcs,
        event_names=event_names,
    )

    table_path = write_amduprof_event_count_table(
        summary_rows=summary_rows,
        out_path=TABLE_DIR / "bench3_amduprof_pmc_event_counts.csv",
    )

    print_amduprof_event_count_table(
        title="[+] Benchmark 3: AMD uProf PMC event counts",
        summary_rows=summary_rows,
    )

    print()
    print(f"[+] Bench 3 AMD uProf input files: {len(result_files)}")
    print(f"[+] Bench 3 unique working PMCs:   {len(working_pmcs)}")
    print(f"[+] AMD uProf event names from:    {AMDUPROF_PCM_EVENTS_FILE}")
    print(f"[+] Wrote table:                   {table_path}")


def analyze_bench4_physical_access_amduprof_pcm_events() -> None:
    result_files = find_benchmark_result_files(bench=4)

    if not result_files:
        print(f"[!] No benchmark 4 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench4_rows = get_bench4_working_pmc_rows(rows)

    if not bench4_rows:
        print("[!] No working benchmark 4 RESULT rows found for AMD uProf event analysis.")
        return

    working_pmcs = unique_working_pmcs(bench4_rows)
    event_names = load_amduprof_pcm_event_names()

    summary_rows = summarize_amduprof_event_counts(
        working_pmcs=working_pmcs,
        event_names=event_names,
    )

    table_path = write_amduprof_event_count_table(
        summary_rows=summary_rows,
        out_path=TABLE_DIR / "bench4_physical_access_amduprof_pmc_event_counts.csv",
    )

    print_amduprof_event_count_table(
        title="[+] Benchmark 4: physical-access AMD uProf PMC event counts",
        summary_rows=summary_rows,
    )

    print()
    print(f"[+] Bench 4 AMD uProf input files: {len(result_files)}")
    print(f"[+] Bench 4 unique working PMCs:   {len(working_pmcs)}")
    print(f"[+] AMD uProf event names from:    {AMDUPROF_PCM_EVENTS_FILE}")
    print(f"[+] Wrote table:                   {table_path}")


# ---------------------------------------------------------------------------
# Benchmark 5: mitigation effectiveness
# ---------------------------------------------------------------------------

def mitigation_name(mitigation: int) -> str:
    if mitigation in MITIGATION_NAMES:
        return MITIGATION_NAMES[mitigation]

    names: List[str] = []

    for bit, name in MITIGATION_NAMES.items():
        if mitigation & bit:
            names.append(name)

    if names:
        return "+".join(names)

    return "NONE"


def get_bench5_mitigation_rows(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    bench5_rows: List[Dict[str, Any]] = []

    for row in rows:
        if row.get("kind") != "RESULT":
            continue

        if row.get("bench") != 5:
            continue

        if row.get("bench_name") != "mitigation_effectiveness":
            continue

        if "mitigation" not in row:
            continue

        if "working_pmcs" not in row:
            continue

        bench5_rows.append(row)

    return bench5_rows


def summarize_bench5_mitigations(
    bench5_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Group benchmark 5 rows by mitigation bitmask.

    For each mitigation:
      - median working_pmcs over all repetitions
      - minimum working_pmcs over all repetitions
      - maximum working_pmcs over all repetitions

    If a known mitigation does not appear, mark it as not_available.
    """
    grouped: Dict[int, List[Dict[str, Any]]] = {}

    for row in bench5_rows:
        mitigation = int(row["mitigation"])
        grouped.setdefault(mitigation, []).append(row)

    summary_rows: List[Dict[str, Any]] = []

    for mitigation in sorted(MITIGATION_NAMES):
        rows_for_mitigation = grouped.get(mitigation)

        if not rows_for_mitigation:
            summary_rows.append(
                {
                    "mitigation": mitigation_name(mitigation),
                    "mitigation_mask": f"0x{mitigation:x}",
                    "working_pmcs_median": "not_available",
                    "working_pmcs_min": "not_available",
                    "working_pmcs_max": "not_available",
                }
            )
            continue

        working_pmcs_values = [
            int(row["working_pmcs"])
            for row in rows_for_mitigation
        ]

        summary_rows.append(
            {
                "mitigation": mitigation_name(mitigation),
                "mitigation_mask": f"0x{mitigation:x}",
                "working_pmcs_median": median(working_pmcs_values),
                "working_pmcs_min": min(working_pmcs_values),
                "working_pmcs_max": max(working_pmcs_values),
            }
        )

    known_masks = set(MITIGATION_NAMES)

    for mitigation in sorted(grouped):
        if mitigation in known_masks:
            continue

        rows_for_mitigation = grouped[mitigation]

        working_pmcs_values = [
            int(row["working_pmcs"])
            for row in rows_for_mitigation
        ]

        summary_rows.append(
            {
                "mitigation": mitigation_name(mitigation),
                "mitigation_mask": f"0x{mitigation:x}",
                "working_pmcs_median": median(working_pmcs_values),
                "working_pmcs_min": min(working_pmcs_values),
                "working_pmcs_max": max(working_pmcs_values),
            }
        )

    return summary_rows


def write_bench5_mitigation_table(summary_rows: List[Dict[str, Any]]) -> Path:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    out_path = TABLE_DIR / "bench5_mitigation_effectiveness.csv"

    fieldnames = [
        "mitigation",
        "mitigation_mask",
        "working_pmcs_median",
        "working_pmcs_min",
        "working_pmcs_max",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            median_value = row["working_pmcs_median"]
            if isinstance(median_value, str):
                median_output = median_value
            else:
                median_output = f"{median_value:.2f}"

            writer.writerow(
                {
                    "mitigation": str(row["mitigation"]),
                    "mitigation_mask": str(row["mitigation_mask"]),
                    "working_pmcs_median": median_output,
                    "working_pmcs_min": row["working_pmcs_min"],
                    "working_pmcs_max": row["working_pmcs_max"],
                }
            )

    return out_path


def print_bench5_mitigation_table(summary_rows: List[Dict[str, Any]]) -> None:
    print()
    print("[+] Benchmark 5: mitigation effectiveness")
    print()
    print(
        f"{'mitigation':<16}  "
        f"{'mask':>8}  "
        f"{'pmcs_med':>10}  "
        f"{'pmcs_min':>10}  "
        f"{'pmcs_max':>10}"
    )
    print("-" * 64)

    for row in summary_rows:
        median_value = row["working_pmcs_median"]
        if isinstance(median_value, str):
            median_output = median_value
        else:
            median_output = f"{median_value:.2f}"

        print(
            f"{str(row['mitigation']):<16}  "
            f"{str(row['mitigation_mask']):>8}  "
            f"{median_output:>10}  "
            f"{str(row['working_pmcs_min']):>10}  "
            f"{str(row['working_pmcs_max']):>10}"
        )


def analyze_bench5_mitigation_effectiveness() -> None:
    result_files = find_benchmark_result_files(bench=5)

    if not result_files:
        print(f"[!] No benchmark 5 JSONL files found in {RESULTS_DIR}")
        return

    rows = load_jsonl_results(result_files)
    bench5_rows = get_bench5_mitigation_rows(rows)

    if not bench5_rows:
        print("[!] No benchmark 5 mitigation_effectiveness RESULT rows found.")
        return

    summary_rows = summarize_bench5_mitigations(bench5_rows)
    table_path = write_bench5_mitigation_table(summary_rows)

    print_bench5_mitigation_table(summary_rows)

    print()
    print(f"[+] Bench 5 input files: {len(result_files)}")
    print(f"[+] Bench 5 input rows:  {len(bench5_rows)}")
    print(f"[+] Wrote table:        {table_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", choices=("run", "analyze"), default="analyze")
    parser.add_argument("target", nargs="?", default="zen3")
    parser.add_argument(
        "--bench",
        "--benches",
        dest="benchmarks",
        type=parse_benchmark_ids,
        help=f"comma-separated benchmark IDs to run; default runs all planned benchmarks ({', '.join(map(str, BENCH_PLAN))})",
    )
    args = parser.parse_args()

    configure_analysis_paths(args.target)

    if args.mode == "run":
        run_all_benchmarks(args.benchmarks)

    analyze_bench1_accuracy_vs_samples()
    analyze_bench9_4k_alias_stlf_accuracy_vs_samples()
    analyze_bench10_scaled_1gib_leak_rate()
    analyze_bench2_secret_length_scaling()

    analyze_bench3_working_pmc_categories()
    analyze_bench3_amduprof_pcm_events()

    merged_histogram_path = write_merged_bench3_threshold_histogram_pdf()
    if merged_histogram_path is not None:
        print(f"[+] Wrote merged bench 3 histogram: {merged_histogram_path}")

    analyze_bench4_physical_access_working_pmc_categories()
    analyze_bench4_physical_access_amduprof_pcm_events()

    analyze_bench5_mitigation_effectiveness()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
