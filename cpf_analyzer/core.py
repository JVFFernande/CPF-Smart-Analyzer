from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Optional


CPF_RE = re.compile(r"^\d{11}$")


def only_digits(value: str) -> str:
    """Remove tudo que não for dígito."""
    return re.sub(r"\D+", "", value or "")


def format_cpf(cpf_digits: str) -> str:
    """Formata 11 dígitos como XXX.XXX.XXX-XX. Não valida."""
    if len(cpf_digits) != 11 or not cpf_digits.isdigit():
        return cpf_digits
    return f"{cpf_digits[0:3]}.{cpf_digits[3:6]}.{cpf_digits[6:9]}-{cpf_digits[9:11]}"


def mask_cpf(cpf_digits: str) -> str:
    """Mascara CPF: ***.***.***-XX (mantém só os 2 últimos)."""
    d = only_digits(cpf_digits)
    if len(d) != 11:
        return cpf_digits
    return f"***.***.***-{d[9:11]}"


def is_repeated_sequence(cpf_digits: str) -> bool:
    """True se for sequência repetida tipo 00000000000, 111..., etc."""
    d = only_digits(cpf_digits)
    return len(d) == 11 and len(set(d)) == 1


def calc_check_digits(base9: str) -> str:
    """
    Calcula os 2 dígitos verificadores para os 9 dígitos base.
    Regra oficial de validação do CPF.
    """
    if len(base9) != 9 or not base9.isdigit():
        raise ValueError("base9 precisa ter 9 dígitos numéricos")

    nums = [int(c) for c in base9]

    # 1º dígito (pesos 10..2)
    s1 = sum(n * w for n, w in zip(nums, range(10, 1, -1)))
    d1 = (s1 * 10) % 11
    d1 = 0 if d1 == 10 else d1

    # 2º dígito (pesos 11..2)
    nums2 = nums + [d1]
    s2 = sum(n * w for n, w in zip(nums2, range(11, 1, -1)))
    d2 = (s2 * 10) % 11
    d2 = 0 if d2 == 10 else d2

    return f"{d1}{d2}"


def validate_cpf(value: str) -> tuple[bool, str, Optional[str]]:
    """
    Valida CPF.
    Retorna: (is_valid, digits11, reason_if_invalid)
    """
    d = only_digits(value)

    if not CPF_RE.match(d):
        return False, d, "CPF deve conter 11 dígitos"

    if is_repeated_sequence(d):
        return False, d, "Sequência repetida (ex.: 00000000000) é inválida"

    base9 = d[:9]
    expected = calc_check_digits(base9)
    got = d[9:]

    if expected != got:
        return False, d, f"Dígitos verificadores inválidos (esperado {expected}, veio {got})"

    return True, d, None


def generate_fake_cpf(formatted: bool = True) -> str:
    """
    Gera CPF FICTÍCIO válido (para testes).
    Não usa nenhuma base real; é aleatório e apenas respeita a regra dos dígitos.
    """
    base9 = "".join(str(random.randint(0, 9)) for _ in range(9))

    # Evita sequência repetida como 000... (raro, mas vamos prevenir)
    while len(set(base9)) == 1:
        base9 = "".join(str(random.randint(0, 9)) for _ in range(9))

    dv = calc_check_digits(base9)
    cpf = base9 + dv
    return format_cpf(cpf) if formatted else cpf


@dataclass(frozen=True)
class CPFAnalysis:
    raw_input: str
    digits: str
    formatted: str
    masked: str
    is_valid: bool
    reason: Optional[str]