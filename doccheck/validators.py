"""Validadores de documentos brasileiros (dígitos verificadores) e utilitários de dados.

Importante: um dígito verificador correto só prova que o NÚMERO é bem formado. Não prova que a pessoa,
a empresa ou o documento existem. Isso só se confirma na fonte oficial (Receita Federal, Detran, emissor).
"""
from __future__ import annotations

import difflib
import re
import unicodedata
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Optional

UFS = {"AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR",
       "PE", "PI", "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"}
CNH_CATEGORIES = {"A", "B", "C", "D", "E", "AB", "AC", "AD", "AE", "ACC"}
PARTICLES = {"DE", "DA", "DO", "DAS", "DOS", "E"}


def only_digits(value) -> str:
    return re.sub(r"\D", "", str(value or ""))


# ---- CPF ---------------------------------------------------------------------------------------
def _cpf_dv(base: str) -> int:
    total = sum(int(d) * w for d, w in zip(base, range(len(base) + 1, 1, -1)))
    rest = (total * 10) % 11
    return 0 if rest == 10 else rest


def valid_cpf(value) -> bool:
    d = only_digits(value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    return d[9] == str(_cpf_dv(d[:9])) and d[10] == str(_cpf_dv(d[:10]))


def make_cpf(base9: str) -> str:
    """Gera um CPF com dígitos corretos a partir de 9 dígitos (usado só nos exemplos e testes)."""
    base = only_digits(base9)[:9].ljust(9, "0")
    first = base + str(_cpf_dv(base))
    return first + str(_cpf_dv(first))


# ---- CNPJ (inclui o formato alfanumérico) --------------------------------------------------------
_W1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_W2 = [6] + _W1


def _cnpj_dv(chars: str, weights) -> int:
    rest = sum((ord(c) - 48) * w for c, w in zip(chars, weights)) % 11   # letras valem ord - 48 (A = 17)
    return 0 if rest < 2 else 11 - rest


def valid_cnpj(value) -> bool:
    c = re.sub(r"[.\-/\s]", "", str(value or "").upper())
    if not re.fullmatch(r"[0-9A-Z]{12}\d{2}", c) or len(set(c)) == 1:
        return False
    d1 = _cnpj_dv(c[:12], _W1)
    d2 = _cnpj_dv(c[:12] + str(d1), _W2)
    return c[12:] == f"{d1}{d2}"


def make_cnpj(base12: str) -> str:
    base = re.sub(r"[.\-/\s]", "", base12.upper())[:12].ljust(12, "0")
    d1 = _cnpj_dv(base, _W1)
    return base + str(d1) + str(_cnpj_dv(base + str(d1), _W2))


# ---- CNH (número de registro) ---------------------------------------------------------------------
def _cnh_dvs(base9: str) -> str:
    """Regra de módulo 11 amplamente usada para o número de registro. NÃO foi conferida com a norma oficial."""
    v = sum(int(c) * (9 - i) for i, c in enumerate(base9))
    dsc, d1 = 0, v % 11
    if d1 >= 10:
        d1, dsc = 0, 2
    v = sum(int(c) * (1 + i) for i, c in enumerate(base9))
    x = v % 11
    d2 = x - dsc if x - dsc >= 0 else x - dsc + 11
    if d2 >= 10:
        d2 = 0
    return f"{d1}{d2}"


def valid_cnh(value) -> bool:
    d = only_digits(value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    return d[9:] == _cnh_dvs(d[:9])


def make_cnh(base9: str) -> str:
    base = only_digits(base9)[:9].ljust(9, "0")
    return base + _cnh_dvs(base)


# ---- CEP, datas, valores ---------------------------------------------------------------------------
def valid_cep(value) -> bool:
    d = only_digits(value)
    return len(d) == 8 and d != "00000000"


def parse_date(value) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def parse_month(value) -> Optional[date]:
    """Competência de holerite: '09/2026' ou '2026-09' viram o dia 1 do mês."""
    text = str(value or "").strip()
    for fmt in ("%m/%Y", "%Y-%m"):
        try:
            return datetime.strptime(text, fmt).date().replace(day=1)
        except ValueError:
            continue
    d = parse_date(text)
    return d.replace(day=1) if d else None


def parse_money(value) -> Optional[Decimal]:
    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        return Decimal(str(value))
    s = re.sub(r"[^\d,.\-]", "", str(value or ""))
    if not s:
        return None
    if "," in s:
        s = s.replace(".", "").replace(",", ".")
    elif s.count(".") > 1 or re.fullmatch(r"-?\d{1,3}\.\d{3}", s):
        s = s.replace(".", "")          # 1.234.567 e 4.500 são separadores de milhar
    try:
        return Decimal(s)
    except InvalidOperation:
        return None


# ---- nomes ---------------------------------------------------------------------------------------
def normalize_name(value) -> str:
    s = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode().upper()
    return " ".join(t for t in re.findall(r"[A-Z]+", s) if t not in PARTICLES)


def name_similarity(a, b) -> float:
    """0 a 1. Ignora acentos, maiúsculas e partículas (DE, DA, DOS...) e aceita iniciais (J. = JOAO)."""
    na, nb = normalize_name(a), normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    ta, tb = na.split(), nb.split()
    abbr = lambda x, y: (len(x) == 1 and y.startswith(x)) or (len(y) == 1 and x.startswith(y))  # noqa: E731
    if len(ta) == len(tb) and all(x == y or abbr(x, y) for x, y in zip(ta, tb)):
        return 0.95
    return difflib.SequenceMatcher(None, na, nb).ratio()


# ---- máscaras (LGPD: minimização de dados nos relatórios) -------------------------------------------
def mask_cpf(value) -> str:
    d = only_digits(value)
    return f"***.{d[3:6]}.{d[6:9]}-**" if len(d) == 11 else "***"


def mask_cnh(value) -> str:
    d = only_digits(value)
    return "*" * 7 + d[-4:] if len(d) >= 4 else "***"
