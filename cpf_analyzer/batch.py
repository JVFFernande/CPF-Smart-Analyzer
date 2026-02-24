from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .report import analyze


@dataclass(frozen=True)
class BatchSummary:
    total: int
    valid: int
    invalid: int
    risk_low: int
    risk_medium: int
    risk_high: int


def _read_txt(path: Path) -> List[str]:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [ln.strip() for ln in lines if ln.strip()]


def _read_csv(path: Path, column: str) -> List[str]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV sem cabeçalho (header).")
        if column not in reader.fieldnames:
            raise ValueError(f"Coluna '{column}' não encontrada. Colunas: {reader.fieldnames}")
        values = []
        for row in reader:
            v = (row.get(column) or "").strip()
            if v:
                values.append(v)
        return values


def load_inputs(path: str, column: str = "cpf") -> List[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))

    ext = p.suffix.lower()
    if ext == ".txt":
        return _read_txt(p)
    if ext == ".csv":
        return _read_csv(p, column=column)

    raise ValueError("Formato não suportado. Use .txt ou .csv")


def run_batch(values: Iterable[str]) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for v in values:
        rep = analyze(v)
        results.append(rep)

    summary = summarize(results)

    return {
        "summary": {
            "total": summary.total,
            "valid": summary.valid,
            "invalid": summary.invalid,
            "risk_low": summary.risk_low,
            "risk_medium": summary.risk_medium,
            "risk_high": summary.risk_high,
        },
        "items": results,
    }


def summarize(reports: List[Dict[str, Any]]) -> BatchSummary:
    total = len(reports)
    valid = sum(1 for r in reports if r["analysis"]["is_valid"])
    invalid = total - valid

    risk_low = sum(1 for r in reports if r["risk_level"] == "low")
    risk_medium = sum(1 for r in reports if r["risk_level"] == "medium")
    risk_high = sum(1 for r in reports if r["risk_level"] == "high")

    return BatchSummary(
        total=total,
        valid=valid,
        invalid=invalid,
        risk_low=risk_low,
        risk_medium=risk_medium,
        risk_high=risk_high,
    )


def write_json(path: str, payload: Dict[str, Any], pretty: bool = True) -> None:
    p = Path(path)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None), encoding="utf-8")


def write_csv(path: str, reports: List[Dict[str, Any]]) -> None:
    p = Path(path)
    headers = [
        "raw_input",
        "digits",
        "formatted",
        "masked",
        "is_valid",
        "reason",
        "risk_score",
        "risk_level",
        "flags_count",
    ]

    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in reports:
            a = r["analysis"]
            row = {
                "raw_input": a["raw_input"],
                "digits": a["digits"],
                "formatted": a["formatted"],
                "masked": a["masked"],
                "is_valid": a["is_valid"],
                "reason": a["reason"] or "",
                "risk_score": r["risk_score"],
                "risk_level": r["risk_level"],
                "flags_count": len(r["flags"]),
            }
            w.writerow(row)