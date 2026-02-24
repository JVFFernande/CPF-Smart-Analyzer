from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .core import only_digits, is_repeated_sequence


@dataclass(frozen=True)
class HeuristicFlag:
    code: str
    severity: str  # "low" | "medium" | "high"
    message: str


def suspicious_flags(value: str) -> List[HeuristicFlag]:
    """
    Heurísticas "inteligentes" (simuladas) para sinalizar entradas suspeitas.
    Não significa fraude — só alerta para qualidade de dado.
    """
    d = only_digits(value)
    flags: List[HeuristicFlag] = []

    if value != d:
        flags.append(HeuristicFlag(
            code="HAS_FORMATTING",
            severity="low",
            message="Entrada contém pontuação/espacos; foi normalizada para dígitos."
        ))

    if len(d) == 0:
        flags.append(HeuristicFlag(
            code="EMPTY",
            severity="high",
            message="Campo vazio."
        ))
        return flags

    if len(d) != 11:
        flags.append(HeuristicFlag(
            code="WRONG_LENGTH",
            severity="high",
            message=f"Tamanho incorreto: {len(d)} dígitos (esperado 11)."
        ))
        return flags

    if is_repeated_sequence(d):
        flags.append(HeuristicFlag(
            code="REPEATED_SEQUENCE",
            severity="high",
            message="Sequência repetida detectada (ex.: 11111111111)."
        ))

    # Heurística simples: muitos dígitos iguais (não invalida, só alerta)
    most_common_count = max(d.count(ch) for ch in set(d))
    if most_common_count >= 8:
        flags.append(HeuristicFlag(
            code="LOW_ENTROPY",
            severity="medium",
            message="Padrão com baixa variabilidade (muitos dígitos iguais)."
        ))

    # Heurística: parece “sequência” (ex.: 123456789..)
    increasing = "0123456789"
    if d[:9] in increasing or d[:9] in increasing[::-1]:
        flags.append(HeuristicFlag(
            code="SEQUENTIAL_BASE",
            severity="medium",
            message="Base do CPF parece sequência (ex.: 123456789)."
        ))

    return flags