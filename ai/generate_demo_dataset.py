"""Generate a reproducible, balanced synthetic dataset for classroom demos."""

import argparse
import csv
import random
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEFAULT_OUTPUT = HERE / "events_train.csv"
FIELDS = (
    "cpu_pct",
    "mem_mb",
    "etype_encoded",
    "hour_of_day",
    "is_sys_dir",
    "proc_count",
    "risk_lvl",
    "data_origin",
)
RISK_LEVELS = ("Normal", "Suspicious", "High Risk")


def generate_row(randomizer: random.Random, risk_level: str) -> dict[str, int | float | str]:
    """Sample plausible feature combinations for one illustrative risk scenario."""
    hour = randomizer.randrange(24)

    if risk_level == "Normal":
        etype = randomizer.choices((0, 1, 2, 3, 4), (72, 8, 14, 4, 2))[0]
        cpu_pct = randomizer.triangular(0, 58, 8)
        mem_mb = randomizer.triangular(20, 1500, 260)
        if randomizer.random() < 0.08:
            cpu_pct = randomizer.uniform(55, 88)
        if randomizer.random() < 0.08:
            mem_mb = randomizer.uniform(1200, 2600)
        is_sys_dir = int(randomizer.random() < 0.38)
        proc_count = randomizer.randint(1, 12)
    elif risk_level == "Suspicious":
        etype = randomizer.choices((0, 1, 2, 3, 4), (7, 32, 32, 24, 5))[0]
        cpu_pct = randomizer.triangular(5, 88, 34)
        mem_mb = randomizer.triangular(80, 2400, 720)
        if randomizer.random() < 0.12:
            cpu_pct = randomizer.uniform(0, 28)
            mem_mb = randomizer.uniform(30, 500)
        is_sys_dir = int(randomizer.random() < 0.25)
        proc_count = randomizer.randint(1, 16)
    elif risk_level == "High Risk":
        etype = randomizer.choices((1, 2, 3, 4), (9, 12, 25, 54))[0]
        cpu_pct = randomizer.triangular(38, 100, 88)
        mem_mb = randomizer.triangular(250, 3600, 1150)
        if randomizer.random() < 0.14:
            cpu_pct = randomizer.uniform(8, 55)
        is_sys_dir = int(randomizer.random() < 0.12)
        proc_count = randomizer.randint(1, 20)
    else:
        raise ValueError(f"Unknown synthetic risk level: {risk_level}")

    return {
        "cpu_pct": round(cpu_pct, 1),
        "mem_mb": round(mem_mb, 1),
        "etype_encoded": etype,
        "hour_of_day": hour,
        "is_sys_dir": is_sys_dir,
        "proc_count": proc_count,
        "risk_lvl": risk_level,
        "data_origin": "synthetic_scenario",
    }


def generate_dataset(output: Path, rows_per_class: int = 300, seed: int = 42) -> None:
    if rows_per_class < 2:
        raise ValueError("rows_per_class must be at least 2")

    randomizer = random.Random(seed)
    rows = [
        generate_row(randomizer, risk_level)
        for risk_level in RISK_LEVELS
        for _ in range(rows_per_class)
    ]
    randomizer.shuffle(rows)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(
        f"Wrote {len(rows)} synthetic rows to {output} "
        f"({rows_per_class} per class; seed={seed})"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--rows-per-class", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    generate_dataset(args.output, args.rows_per_class, args.seed)


if __name__ == "__main__":
    main()
