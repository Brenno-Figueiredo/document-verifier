"""Linha de comando do DocCheck."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date

from . import __version__, forensics, report
from .findings import SEV_LABEL
from .rules import run_check
from .samples import write_samples
from .validators import mask_cnh, mask_cpf, valid_cep, valid_cnh, valid_cnpj, valid_cpf

CHECKS = {"cpf": valid_cpf, "cnpj": valid_cnpj, "cnh": valid_cnh, "cep": valid_cep}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="doccheck", description="Apoio à conferência de documentos: regras, cruzamentos e análise de arquivos.",
        epilog="Aponta divergências para revisão humana. Não prova a autenticidade de documentos.")
    sub = ap.add_subparsers(dest="cmd")

    ck = sub.add_parser("check", help="confere uma ficha (JSON) com proposta e documentos")
    ck.add_argument("ficha")
    ck.add_argument("--json", metavar="ARQ.json")
    ck.add_argument("--html", metavar="ARQ.html", help="gera o parecer em HTML")
    ck.add_argument("--today", metavar="AAAA-MM-DD", help="data de referência (padrão: hoje)")
    ck.add_argument("--no-color", action="store_true")

    fo = sub.add_parser("forensics", help="inspeciona metadados de arquivos PDF/JPEG/PNG")
    fo.add_argument("files", nargs="+")

    va = sub.add_parser("validate", help="valida o dígito verificador de um número")
    va.add_argument("kind", choices=sorted(CHECKS))
    va.add_argument("value")

    sm = sub.add_parser("samples", help="gera fichas e arquivos de exemplo (fictícios)")
    sm.add_argument("--dir", default="samples")

    sv = sub.add_parser("serve", help="abre a interface web local")
    sv.add_argument("--port", type=int, default=8900)
    sv.add_argument("--no-browser", action="store_true")

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def cmd_check(args) -> int:
    try:
        with open(args.ficha, encoding="utf-8") as f:
            ficha = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"Erro ao ler {args.ficha}: {exc}", file=sys.stderr)
        return 2
    if args.today:
        ficha["data_referencia"] = args.today
    result = run_check(ficha, base_dir=os.path.dirname(os.path.abspath(args.ficha)), allow_paths=True)
    print(report.render_text(result, color=not args.no_color and sys.stdout.isatty()))
    for path, render in ((args.json, report.to_json), (args.html, report.render_html)):
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(render(result))
            print(f"\nSalvo em: {path}")
    return 1 if result["level"] in ("critical", "high") else 0


def cmd_forensics(args) -> int:
    worst = 0
    for path in args.files:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as exc:
            print(f"{path}: {exc.strerror}", file=sys.stderr)
            continue
        info = forensics.inspect(data, os.path.basename(path), date.today())
        print(f"\n{path}\n  tipo: {info['type']}  tamanho: {info['size']} bytes  SHA-256: {info['sha256'][:16]}...")
        for key, value in info["meta"].items():
            if value not in (None, False, ""):
                print(f"  {key}: {value}")
        for fd in info["findings"]:
            worst = max(worst, 1 if fd.severity in ("high", "critical") else 0)
            print(f"  [{SEV_LABEL[fd.severity]}] {fd.title}: {fd.detail}")
        if not info["findings"]:
            print("  Nenhum sinal de edição nos metadados.")
    return worst


def cmd_validate(args) -> int:
    ok = CHECKS[args.kind](args.value)
    shown = mask_cpf(args.value) if args.kind == "cpf" else mask_cnh(args.value) if args.kind == "cnh" else args.value
    print(f"{args.kind.upper()} {shown}: {'dígitos verificadores corretos' if ok else 'inválido'}")
    if ok and args.kind != "cep":
        print("Atenção: número bem formado não prova que a pessoa ou empresa existe.")
    return 0 if ok else 1


def cmd_samples(args) -> int:
    for name in write_samples(args.dir):
        print(f"criado: {os.path.join(args.dir, name)}")
    print(f"\nTeste com: python app.py check {os.path.join(args.dir, 'ficha_divergente.json')}")
    return 0


def cmd_serve(args) -> int:
    from .server import serve
    serve(args.port, not args.no_browser)
    return 0


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    return {"check": cmd_check, "forensics": cmd_forensics, "validate": cmd_validate,
            "samples": cmd_samples, "serve": cmd_serve}[args.cmd](args)
