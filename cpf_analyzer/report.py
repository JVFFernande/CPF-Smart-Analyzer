from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List, Literal

from .core import CPFAnalysis, format_cpf, mask_cpf, validate_cpf, only_digits
from .heuristics import suspicious_flags, HeuristicFlag

RiskLevel = Literal["low", "medium", "high"]


def analyze(value: str) -> Dict[str, Any]:
    digits = only_digits(value)
    is_valid, digits_out, reason = validate_cpf(value)

    analysis = CPFAnalysis(
        raw_input=value,
        digits=digits_out,
        formatted=format_cpf(digits_out),
        masked=mask_cpf(digits_out),
        is_valid=is_valid,
        reason=reason,
    )

    flags = suspicious_flags(value)
    score = risk_score(flags=flags, is_valid=is_valid, digits_len=len(digits))
    level = risk_level(score)

    return {
        "analysis": asdict(analysis),
        "flags": [asdict(f) for f in flags],
        "risk_score": score,
        "risk_level": level,
        "disclaimer": (
            "Projeto de portfólio (simulado). "
            "Não use para validar identidade real ou tomar decisões legais/financeiras."
        ),
    }


def risk_score(*, flags: List[HeuristicFlag], is_valid: bool, digits_len: int) -> int:
    score = 0

    if digits_len == 0:
        return 100

    code_set = {f.code for f in flags}

    if digits_len != 11:
        score += 80
    elif not is_valid:
        score += 55
    else:
        score += 5

    code_weights = {
        "EMPTY": 100,
        "WRONG_LENGTH": 80,
        "REPEATED_SEQUENCE": 70,
        "SEQUENTIAL_BASE": 35,
        "LOW_ENTROPY": 25,
        "HAS_FORMATTING": 3,
    }

    severity_weights = {"low": 2, "medium": 8, "high": 15}

    for f in flags:
        score += code_weights.get(f.code, 5)
        score += severity_weights.get(f.severity, 2)

    if "REPEATED_SEQUENCE" in code_set and (not is_valid or digits_len != 11):
        score += 20

    if "SEQUENTIAL_BASE" in code_set and not is_valid:
        score += 10

    if is_valid and code_set == {"HAS_FORMATTING"}:
        score = min(score, 10)

    return max(0, min(100, score))


def risk_level(score: int) -> RiskLevel:
    if score <= 20:
        return "low"
    if score <= 55:
        return "medium"
    return "high"


def to_json(report: Dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2 if pretty else None)