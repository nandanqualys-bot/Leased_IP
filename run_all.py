#!/usr/bin/env python3
"""
run_all.py
One-command runner for the complete EASM off-ASN workflow.

Usage:
    python run_all.py --input targets.xlsx

Behavior:
1. Runs discovery.
2. As soon as off_asn_candidates.xlsx exists, opens it in Excel on Windows.
3. Immediately starts verification while the user can inspect the discovery workbook.
4. Produces the final verified workbook and JSON.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd: list[str]) -> None:
    print("\n" + "=" * 75, flush=True)
    print("RUNNING:", " ".join(str(x) for x in cmd), flush=True)
    print("=" * 75, flush=True)

    # No capture=True: discovery/verification progress is visible live.
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(
            f"Process failed with exit code {result.returncode}: {' '.join(cmd)}"
        )


def open_in_excel(path: Path) -> bool:
    """Open the discovery workbook on Windows without blocking the pipeline."""
    if not path.exists():
        return False

    if sys.platform.startswith("win"):
        try:
            os.startfile(str(path))
            print(f"\n[VIEW] Opened discovery workbook in Excel: {path.resolve()}", flush=True)
            return True
        except Exception as exc:
            print(f"[VIEW] Could not automatically open Excel: {exc}", flush=True)

    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the complete EASM off-ASN discovery + verification workflow."
    )
    parser.add_argument(
        "--input",
        default="targets.xlsx",
        help="Input target file. Default: targets.xlsx",
    )
    parser.add_argument(
        "--candidate-output",
        default="off_asn_candidates.xlsx",
        help="Discovery Excel output.",
    )
    parser.add_argument(
        "--candidate-json",
        default="off_asn_candidates.json",
        help="Discovery JSON handoff.",
    )
    parser.add_argument(
        "--final-output",
        default="verified_ip_ranges.xlsx",
        help="Final verification Excel output.",
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Configuration file.",
    )
    parser.add_argument("--workers", type=int, help="Override worker count.")
    parser.add_argument("--timeout", type=float, help="Override HTTP timeout.")
    parser.add_argument(
        "--no-open-excel",
        action="store_true",
        help="Do not automatically open the discovery workbook.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow outputs to be overwritten.",
    )

    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = root / input_path

    candidate_output = Path(args.candidate_output)
    if not candidate_output.is_absolute():
        candidate_output = root / candidate_output

    candidate_json = Path(args.candidate_json)
    if not candidate_json.is_absolute():
        candidate_json = root / candidate_json

    final_output = Path(args.final_output)
    if not final_output.is_absolute():
        final_output = root / final_output

    config = Path(args.config)
    if not config.is_absolute():
        config = root / config

    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        print(f"Put your input file in: {root}", file=sys.stderr)
        return 1

    python = sys.executable

    print("\n" + "#" * 75)
    print("# EASM OFF-ASN ONE-COMMAND PIPELINE")
    print("#" * 75)
    print(f"Input: {input_path}")
    print("Stage 1: Discovery")
    print("Stage 2: Verification")
    print("The discovery workbook will be opened automatically before verification.")
    print("#" * 75)

    discovery_cmd = [
        python,
        str(root / "02_off_asn_discovery.py"),
        "--input",
        str(input_path),
        "--output",
        str(candidate_output),
        "--json-output",
        str(candidate_json),
        "--config",
        str(config),
    ]

    if args.workers:
        discovery_cmd += ["--workers", str(args.workers)]
    if args.timeout:
        discovery_cmd += ["--timeout", str(args.timeout)]
    if args.overwrite:
        discovery_cmd += ["--overwrite"]

    try:
        print("\n[1/2] DISCOVERY STARTED", flush=True)
        run_command(discovery_cmd)

        if not candidate_json.exists():
            raise RuntimeError(
                "Discovery completed but the JSON handoff file was not created."
            )

        if not candidate_output.exists():
            raise RuntimeError(
                "Discovery completed but the Excel output was not created."
            )

        print("\n" + "-" * 75)
        print("[HANDOFF] Discovery finished successfully.")
        print(f"[HANDOFF] Excel: {candidate_output.resolve()}")
        print(f"[HANDOFF] JSON : {candidate_json.resolve()}")
        print("-" * 75)

        # Give the filesystem a moment to release the workbook before Excel opens it.
        time.sleep(1)

        if not args.no_open_excel:
            opened = open_in_excel(candidate_output)
            if not opened:
                print(
                    f"[VIEW] Open this file manually while verification runs:\n"
                    f"       {candidate_output.resolve()}",
                    flush=True,
                )

        verification_cmd = [
            python,
            str(root / "04_ip_verification.py"),
            "--input",
            str(candidate_json),
            "--output",
            str(final_output),
            "--config",
            str(config),
        ]

        if args.workers:
            verification_cmd += ["--workers", str(args.workers)]
        if args.timeout:
            verification_cmd += ["--timeout", str(args.timeout)]
        if args.overwrite:
            verification_cmd += ["--overwrite"]

        print("\n[2/2] VERIFICATION STARTED", flush=True)
        print(
            "[2/2] You can now inspect the discovery Excel workbook while "
            "verification is running.",
            flush=True,
        )
        run_command(verification_cmd)

        final_json = final_output.with_suffix(".json")

        print("\n" + "#" * 75)
        print("# COMPLETE")
        print("#" * 75)
        print(f"Discovery Excel : {candidate_output.resolve()}")
        print(f"Discovery JSON  : {candidate_json.resolve()}")
        print(f"Final Excel     : {final_output.resolve()}")
        print(f"Final JSON      : {final_json.resolve()}")
        print("#" * 75)
        print("\nYou only needed one command.")
        return 0

    except KeyboardInterrupt:
        print("\nPipeline cancelled by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"\nPIPELINE ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
