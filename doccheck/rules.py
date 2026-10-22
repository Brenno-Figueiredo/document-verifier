"""Regras de conferência: cada documento sozinho e os documentos entre si.

O resultado são "achados" para uma PESSOA revisar. O programa nunca aprova nem reprova um cliente.
"""
from __future__ import annotations

import base64
import binascii
import os
from datetime import date, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Tuple

from . import forensics
from .findings import SEV_ORDER, SEV_WEIGHT, Finding
from .validators import (CNH_CATEGORIES, UFS, mask_cnh, mask_cpf, name_similarity, only_digits, parse_date,
                         parse_money, parse_month, valid_cep, valid_cnh, valid_cnpj, valid_cpf)

MAX_FILE = 15 * 1024 * 1024
DEFAULTS = {"max_age_days": 90, "cnh_max_years": 10, "money_tolerance": "0.05", "income_margin": 0.05,
            "name_ok": 0.97, "name_similar": 0.75}
LABEL = {"cnh": "CNH", "comprovante_endereco": "Comprovante de endereço", "comprovante_renda": "Comprovante de renda"}
NOTE = ("Este resultado aponta divergências para revisão humana. Ele NÃO prova que um documento é autêntico: "
        "isso só se confirma na fonte oficial (Detran/QR Code da CNH, Receita Federal, o emissor do documento).")


def brl(value: Decimal) -> str:
    return "R$ " + f"{value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def _years(start: date, end: date) -> int:
    return end.year - start.year - ((end.month, end.day) < (start.month, start.day))


# ---- documentos individuais -----------------------------------------------------------------------------
def check_cnh(d: dict, today: date, cfg: dict) -> List[Finding]:
    L, f = LABEL["cnh"], []
    num = only_digits(d.get("numero_registro"))
    if not num:
        f.append(Finding("medium", "campo_ausente", "Número de registro da CNH não informado", "", L))
    elif not valid_cnh(num):
        f.append(Finding("medium", "cnh_numero", "Número de registro da CNH com dígito verificador inconsistente",
                         f"Número {mask_cnh(num)}. A regra aplicada confere o formato; não é consulta oficial.", L))
    if d.get("cpf") and not valid_cpf(d["cpf"]):
        f.append(Finding("high", "cpf_invalido", "CPF da CNH inválido", f"CPF {mask_cpf(d['cpf'])} não passa nos dígitos verificadores.", L))
    cat = str(d.get("categoria") or "").upper().replace(" ", "")
    if cat and cat not in CNH_CATEGORIES:
        f.append(Finding("medium", "cnh_numero", f"Categoria '{cat}' não existe", "Categorias válidas: " + ", ".join(sorted(CNH_CATEGORIES)), L))
    nasc, prim = parse_date(d.get("data_nascimento")), parse_date(d.get("primeira_habilitacao"))
    emi, val = parse_date(d.get("data_emissao")), parse_date(d.get("validade"))
    seq = [(n, x) for n, x in (("nascimento", nasc), ("primeira habilitação", prim), ("emissão", emi), ("validade", val)) if x]
    problems = [f"{a} ({x:%d/%m/%Y}) é depois de {b} ({y:%d/%m/%Y})" for (a, x), (b, y) in zip(seq, seq[1:]) if x > y]
    if nasc and prim and _years(nasc, prim) < 18:
        problems.append("primeira habilitação antes dos 18 anos")
    if problems:
        f.append(Finding("high", "datas_incoerentes", "Datas da CNH incoerentes entre si", "; ".join(problems) + ".", L))
    if val and val < today:
        f.append(Finding("high", "cnh_vencida", "CNH vencida", f"Validade em {val:%d/%m/%Y}, há {(today - val).days} dia(s).", L))
    if emi and val and (val - emi).days > cfg["cnh_max_years"] * 366 + 30:
        f.append(Finding("medium", "datas_incoerentes", "Prazo de validade acima do usual",
                         f"Emissão {emi:%d/%m/%Y} e validade {val:%d/%m/%Y}: mais de {cfg['cnh_max_years']} anos.", L))
    return f


def check_endereco(d: dict, today: date, cfg: dict) -> List[Finding]:
    L, f = LABEL["comprovante_endereco"], []
    emi = parse_date(d.get("data_emissao"))
    if not emi:
        f.append(Finding("low", "campo_ausente", "Data de emissão do comprovante não informada", "", L))
    elif emi > today:
        f.append(Finding("high", "data_futura", "Comprovante com data no futuro", f"Emissão em {emi:%d/%m/%Y}.", L))
    elif (today - emi).days > cfg["max_age_days"]:
        f.append(Finding("medium", "comprovante_antigo", "Comprovante de endereço antigo",
                         f"Emitido há {(today - emi).days} dias (limite da política: {cfg['max_age_days']}).", L))
    if d.get("cep") and not valid_cep(d["cep"]):
        f.append(Finding("medium", "cep_invalido", "CEP inválido", f"CEP '{d['cep']}' não tem 8 dígitos.", L))
    if d.get("uf") and str(d["uf"]).upper() not in UFS:
        f.append(Finding("low", "campo_ausente", f"UF '{d['uf']}' não existe", "", L))
    return f


def check_renda(d: dict, proposta: dict, today: date, cfg: dict) -> List[Finding]:
    L, f = LABEL["comprovante_renda"], []
    comp = parse_month(d.get("competencia"))
    if not comp:
        f.append(Finding("low", "campo_ausente", "Competência do comprovante de renda não informada", "", L))
    elif comp > today:
        f.append(Finding("high", "data_futura", "Competência no futuro", f"{comp:%m/%Y} é depois da data de referência.", L))
    elif (today - comp).days - 30 > cfg["max_age_days"]:
        f.append(Finding("medium", "comprovante_antigo", "Comprovante de renda antigo",
                         f"Competência {comp:%m/%Y}, fora do prazo de {cfg['max_age_days']} dias.", L))
    if d.get("cnpj_empregador") and not valid_cnpj(d["cnpj_empregador"]):
        f.append(Finding("high", "cnpj_invalido", "CNPJ do empregador inválido",
                         f"'{d['cnpj_empregador']}' não passa nos dígitos verificadores.", L))
    if d.get("cpf") and not valid_cpf(d["cpf"]):
        f.append(Finding("high", "cpf_invalido", "CPF do comprovante de renda inválido", f"CPF {mask_cpf(d['cpf'])}.", L))
    gross, disc, net = (parse_money(d.get(k)) for k in ("bruto", "descontos", "liquido"))
    if gross is not None and disc is not None and net is not None:
        if abs(gross - disc - net) > Decimal(str(cfg["money_tolerance"])):
            f.append(Finding("high", "conta_nao_fecha", "As contas do holerite não fecham",
                             f"Bruto {brl(gross)} - descontos {brl(disc)} = {brl(gross - disc)}, mas o líquido informado é {brl(net)}.", L))
    declared = parse_money(proposta.get("renda_declarada"))
    if declared is not None and gross is not None and declared > gross * Decimal(str(1 + cfg["income_margin"])):
        f.append(Finding("high", "renda_acima", "Renda declarada maior que a comprovada",
                         f"Declarada {brl(declared)}; rendimento bruto comprovado {brl(gross)}.", L))
    return f


# ---- arquivos ---------------------------------------------------------------------------------------------------
def load_file(doc: dict, base_dir: Optional[str], allow_paths: bool) -> Tuple[Optional[bytes], str, Optional[str]]:
    """Devolve (bytes, nome, erro). Caminhos de arquivo só valem na linha de comando, nunca no servidor."""
    if doc.get("arquivo_b64"):
        try:
            return base64.b64decode(doc["arquivo_b64"], validate=True), str(doc.get("arquivo_nome") or "arquivo"), None
        except (binascii.Error, ValueError):
            return None, "arquivo", "conteúdo do arquivo não é base64 válido"
    if doc.get("arquivo") and allow_paths:
        path = os.path.join(base_dir or ".", str(doc["arquivo"]))
        try:
            if os.path.getsize(path) > MAX_FILE:
                return None, os.path.basename(path), "arquivo maior que 15 MB"
            with open(path, "rb") as fh:
                return fh.read(), os.path.basename(path), None
        except OSError as exc:
            return None, os.path.basename(path), f"não foi possível ler: {exc.strerror}"
    return None, "", None


# ---- cruzamentos entre documentos -----------------------------------------------------------------------------------
def cross_checks(proposta: dict, docs: dict, inspections: dict, today: date, cfg: dict) -> List[Finding]:
    f: List[Finding] = []
    name = proposta.get("nome")
    for key, d in docs.items():
        if name and d.get("nome"):
            sim = name_similarity(name, d["nome"])
            if sim >= cfg["name_ok"]:
                continue
            if sim >= cfg["name_similar"]:
                f.append(Finding("low", "nome_similar", "Nome com grafia diferente",
                                 f"'{d['nome']}' no documento e '{name}' na proposta (semelhança {sim:.0%}).", LABEL[key]))
            else:
                sev = "medium" if key == "comprovante_endereco" else "high"
                f.append(Finding(sev, "nome_diverge", "Nome do documento diverge do proponente",
                                 f"'{d['nome']}' no documento e '{name}' na proposta (semelhança {sim:.0%}).", LABEL[key]))
    cpfs: Dict[str, List[str]] = {}
    for origin, value in [("proposta", proposta.get("cpf"))] + [(LABEL[k], d.get("cpf")) for k, d in docs.items()]:
        if value:
            cpfs.setdefault(only_digits(value), []).append(origin)
    if len(cpfs) > 1:
        f.append(Finding("critical", "cpf_diverge", "CPFs diferentes entre os documentos",
                         "; ".join(f"{mask_cpf(c)} em {', '.join(o)}" for c, o in cpfs.items()) + ".", "Cruzamento"))
    cnh = docs.get("cnh", {})
    born_a, born_b = parse_date(proposta.get("data_nascimento")), parse_date(cnh.get("data_nascimento"))
    if born_a and born_b and born_a != born_b:
        f.append(Finding("critical", "nascimento_diverge", "Data de nascimento diverge entre proposta e CNH",
                         f"{born_a:%d/%m/%Y} na proposta e {born_b:%d/%m/%Y} na CNH.", "Cruzamento"))
    addr, proof = proposta.get("endereco") or {}, docs.get("comprovante_endereco", {})
    if addr.get("cep") and proof.get("cep") and only_digits(addr["cep"]) != only_digits(proof["cep"]):
        f.append(Finding("medium", "cep_diverge", "CEP do comprovante diferente do informado na proposta",
                         f"{addr['cep']} na proposta e {proof['cep']} no comprovante.", "Cruzamento"))
    elif addr.get("numero") and proof.get("numero") and str(addr["numero"]).strip() != str(proof["numero"]).strip():
        f.append(Finding("low", "cep_diverge", "Número do endereço diferente",
                         f"{addr['numero']} na proposta e {proof['numero']} no comprovante.", "Cruzamento"))
    seen: Dict[str, str] = {}
    for key, info in inspections.items():
        digest = info["sha256"]
        if digest in seen:
            f.append(Finding("high", "arquivo_duplicado", "O mesmo arquivo foi enviado como dois documentos",
                             f"{LABEL[seen[digest]]} e {LABEL[key]} são o mesmo arquivo.", "Cruzamento"))
        seen[digest] = key
        issued = parse_date(docs[key].get("data_emissao")) or parse_month(docs[key].get("competencia"))
        created = (info["meta"] or {}).get("created")
        made = forensics._iso(created) if created and "T" in str(created) else forensics._exif_dt(created)
        if issued and made and made.date() < issued - timedelta(days=1):
            f.append(Finding("high", "arquivo_criado_antes", "Arquivo criado antes da data de emissão do documento",
                             f"O arquivo foi criado em {made:%d/%m/%Y}, mas o documento diz ter sido emitido em {issued:%d/%m/%Y}.", LABEL[key]))
    return f


# ---- orquestração -----------------------------------------------------------------------------------------------------
def summarize(findings: List[Finding]) -> dict:
    counts = {s: sum(1 for x in findings if x.severity == s) for s in SEV_ORDER}
    risk = min(100, sum(x.weight for x in findings))
    if counts["critical"]:
        level, verdict = "critical", "Divergências graves: não prosseguir sem revisão"
    elif risk >= 40:
        level, verdict = "high", "Revisão manual obrigatória"
    elif risk >= 12:
        level, verdict = "medium", "Atenção: conferir os pontos abaixo"
    elif risk > 0:
        level, verdict = "low", "Pequenos pontos de atenção"
    else:
        level, verdict = "ok", "Nenhuma divergência nas regras verificadas"
    return {"risk": risk, "level": level, "verdict": verdict, "counts": counts}


def run_check(ficha: dict, base_dir: Optional[str] = None, allow_paths: bool = False, config: Optional[dict] = None) -> dict:
    cfg = {**DEFAULTS, **(ficha.get("configuracao") or {}), **(config or {})}
    today = parse_date(ficha.get("data_referencia")) or date.today()
    proposta = ficha.get("proposta") or {}
    docs = {k: v for k, v in (ficha.get("documentos") or {}).items() if k in LABEL and isinstance(v, dict)}
    findings: List[Finding] = []
    checkers = {"cnh": lambda d: check_cnh(d, today, cfg), "comprovante_endereco": lambda d: check_endereco(d, today, cfg),
                "comprovante_renda": lambda d: check_renda(d, proposta, today, cfg)}
    inspections: Dict[str, dict] = {}
    for key, d in docs.items():
        findings += checkers[key](d)
        data, fname, error = load_file(d, base_dir, allow_paths)
        if error:
            findings.append(Finding("low", "sem_metadados", "Arquivo não pôde ser inspecionado", error, LABEL[key]))
        elif data is not None:
            info = forensics.inspect(data, fname, today)
            for fd in info.pop("findings"):
                fd.doc = LABEL[key]
                findings.append(fd)
            inspections[key] = info
    findings += cross_checks(proposta, docs, inspections, today, cfg)
    findings.sort(key=lambda x: (SEV_ORDER.index(x.severity), x.doc))
    return {
        **summarize(findings), "note": NOTE, "reference_date": today.isoformat(),
        "proponent": {"nome": proposta.get("nome"), "cpf": mask_cpf(proposta.get("cpf")) if proposta.get("cpf") else None},
        "documents": [LABEL[k] for k in docs],
        "files": [{"doc": LABEL[k], "name": i["name"], "type": i["type"], "size": i["size"], "sha256": i["sha256"][:16],
                   "producer": (i["meta"] or {}).get("producer") or (i["meta"] or {}).get("software"),
                   "created": (i["meta"] or {}).get("created")} for k, i in inspections.items()],
        "findings": [x.to_dict() for x in findings],
    }
