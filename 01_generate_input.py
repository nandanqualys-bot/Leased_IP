#!/usr/bin/env python3
"""
01_generate_input.py
Create/validate targets.xlsx and targets.json for the off-ASN EASM pipeline.
"""

from __future__ import annotations
import argparse
import csv
import json
import re
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

import pandas as pd

COLUMNS = [
    "Parent_Organization",
    "Target_Entity",
    "Target_Domain",
    "Known_Target_ASNs",
    "Known_Registrant_Names",
]

ASN_RE = re.compile(r"^AS\d+$", re.I)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.I,
)


def norm_text(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return re.sub(r"\s+", " ", str(value).strip())


def normalize_domain(value: str) -> str:
    value = norm_text(value).lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.rstrip(".")
    return value


def normalize_asn(value: str) -> str:
    value = norm_text(value).upper()
    if not value:
        return ""
    if value.isdigit():
        return f"AS{value}"
    return value if value.startswith("AS") else f"AS{value}"


def split_values(value: str) -> list[str]:
    return [x.strip() for x in norm_text(value).split(";") if x.strip()]


def validate_rows(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[COLUMNS].copy()
    for c in COLUMNS:
        df[c] = df[c].map(norm_text)

    errors = []
    for idx, row in df.iterrows():
        line = idx + 2
        if not row["Parent_Organization"]:
            errors.append(f"Row {line}: Parent_Organization is empty")
        domains = split_values(row["Target_Domain"])
        if not domains:
            errors.append(f"Row {line}: Target_Domain is empty")
        for d in domains:
            d = normalize_domain(d)
            if not DOMAIN_RE.match(d):
                errors.append(f"Row {line}: invalid domain: {d}")
        for a in split_values(row["Known_Target_ASNs"]):
            a = normalize_asn(a)
            if not ASN_RE.match(a):
                errors.append(f"Row {line}: invalid ASN: {a}")
        if not row["Target_Entity"]:
            df.at[idx, "Target_Entity"] = row["Parent_Organization"]

        df.at[idx, "Target_Domain"] = ";".join(
            dict.fromkeys(normalize_domain(x) for x in domains)
        )
        df.at[idx, "Known_Target_ASNs"] = ";".join(
            dict.fromkeys(normalize_asn(x) for x in split_values(row["Known_Target_ASNs"]))
        )
        df.at[idx, "Known_Registrant_Names"] = ";".join(
            dict.fromkeys(split_values(row["Known_Registrant_Names"]))
        )

    if errors:
        raise ValueError("\n".join(errors))

    dup_cols = ["Parent_Organization", "Target_Entity", "Target_Domain", "Known_Target_ASNs"]
    dup = df.duplicated(subset=dup_cols, keep=False)
    if dup.any():
        vals = df.loc[dup, dup_cols].to_dict("records")
        raise ValueError(f"Duplicate target rows detected: {vals}")

    return df


def load_input(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(path, dtype=str).fillna("")
    if suffix == ".csv":
        return pd.read_csv(path, dtype=str).fillna("")
    if suffix == ".json":
        obj = json.loads(path.read_text(encoding="utf-8"))
        rows = obj.get("targets", obj) if isinstance(obj, dict) else obj
        if not isinstance(rows, list):
            raise ValueError("JSON must contain a 'targets' array or be an array.")
        out = []
        for t in rows:
            out.append({
                "Parent_Organization": t.get("parent_organization", t.get("Parent_Organization", "")),
                "Target_Entity": t.get("target_entity", t.get("Target_Entity", "")),
                "Target_Domain": ";".join(t.get("target_domains", [])) if isinstance(t.get("target_domains"), list) else t.get("Target_Domain", ""),
                "Known_Target_ASNs": ";".join(t.get("known_asns", [])) if isinstance(t.get("known_asns"), list) else t.get("Known_Target_ASNs", ""),
                "Known_Registrant_Names": ";".join(t.get("known_registrant_names", [])) if isinstance(t.get("known_registrant_names"), list) else t.get("Known_Registrant_Names", ""),
            })
        return pd.DataFrame(out)
    raise ValueError("Supported input formats: .xlsx, .xls, .csv, .json")


def interactive_rows() -> pd.DataFrame:
    print("Interactive target creation. Press Ctrl+C to cancel.")
    rows = []
    while True:
        parent = input("Parent organization: ").strip()
        entity = input("Target entity [blank = parent]: ").strip() or parent
        domains = input("Target domain(s), separated by ';': ").strip()
        asns = input("Known ASN(s), separated by ';' [optional]: ").strip()
        registrants = input("Known registrant name(s), separated by ';' [optional]: ").strip()
        rows.append({
            "Parent_Organization": parent,
            "Target_Entity": entity,
            "Target_Domain": domains,
            "Known_Target_ASNs": asns,
            "Known_Registrant_Names": registrants,
        })
        more = input("Add another target? [y/N]: ").strip().lower()
        if more != "y":
            break
    return pd.DataFrame(rows)


def to_json(df: pd.DataFrame) -> dict[str, Any]:
    targets = []
    for _, row in df.iterrows():
        targets.append({
            "parent_organization": row["Parent_Organization"],
            "target_entity": row["Target_Entity"],
            "target_domains": split_values(row["Target_Domain"]),
            "known_asns": split_values(row["Known_Target_ASNs"]),
            "known_registrant_names": split_values(row["Known_Registrant_Names"]),
        })
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
    }


def safe_output(path: Path, overwrite: bool) -> Path:
    if overwrite or not path.exists():
        return path
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return path.with_name(f"{path.stem}_{stamp}{path.suffix}")


def main() -> int:
    p = argparse.ArgumentParser(description="Generate and validate EASM target input.")
    p.add_argument("--input", help="Existing CSV/XLSX/JSON input.")
    p.add_argument("--output", default="targets.xlsx")
    p.add_argument("--json-output", default="targets.json")
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args()

    try:
        df = load_input(Path(args.input)) if args.input else interactive_rows()
        df = validate_rows(df)

        xlsx = safe_output(Path(args.output), args.overwrite)
        js = safe_output(Path(args.json_output), args.overwrite)
        df.to_excel(xlsx, index=False)
        js.write_text(json.dumps(to_json(df), indent=2), encoding="utf-8")

        print(f"Created Excel: {xlsx.resolve()}")
        print(f"Created JSON : {js.resolve()}")
        print(f"Targets      : {len(df)}")
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
