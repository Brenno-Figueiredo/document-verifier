"""Saídas do parecer: texto, JSON e HTML (tudo escapado; CPF sempre mascarado)."""
from __future__ import annotations

import html
import json
from datetime import datetime

from .findings import SEV_LABEL

ANSI = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[1;34m",
        "info": "\033[2m", "ok": "\033[1;32m", "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m"}
COLOR = {"critical": "#ff5c7a", "high": "#ff9a45", "medium": "#f2cd3b", "low": "#5aa9ff", "info": "#8ba0b2", "ok": "#3ddc84"}


def render_text(result: dict, color: bool = False) -> str:
    p = (lambda t, k: f"{ANSI[k]}{t}{ANSI['reset']}") if color else (lambda t, k: t)
    who = result["proponent"]
    lines = [p("PARECER DE CONFERÊNCIA", "bold"),
             f"Proponente: {who.get('nome') or '-'}  CPF: {who.get('cpf') or '-'}",
             f"Documentos: {', '.join(result['documents']) or '-'}  Data de referência: {result['reference_date']}",
             "", p(f" {result['verdict'].upper()} ", result["level"]) + f"  (nota de atenção {result['risk']}/100)", ""]
    for fd in result["findings"]:
        lines.append(f"{p('[' + SEV_LABEL[fd['severity']] + ']', fd['severity'])} {fd['title']}  ({fd['doc']})")
        if fd["detail"]:
            lines.append(f"    {fd['detail']}")
        if fd["action"]:
            lines.append(p(f"    -> {fd['action']}", "dim"))
    if not result["findings"]:
        lines.append("Nenhuma divergência encontrada nas regras verificadas.")
    lines += ["", p(result["note"], "dim")]
    return "\n".join(lines)


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)


CSS = """
:root{color-scheme:dark;--bg:#0c1219;--panel:#141e29;--line:#25364a;--text:#e5edf4;--muted:#8aa0b3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:30px 22px 70px}h1{margin:0;font-size:26px}.sub{color:var(--muted);margin:4px 0 0}
.verdict{margin:22px 0;padding:18px;border:1px solid var(--line);border-left-width:5px;border-radius:12px;background:var(--panel)}
.verdict b{font-size:20px}.f{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:12px 15px;margin:9px 0}
.f .t{font-weight:600}.badge{font-size:11.5px;font-weight:700;border-radius:999px;padding:1px 9px;color:#08121a;margin-right:6px}
.d,.a{color:var(--muted);font-size:13px;margin-top:3px}.a{color:#9ad9c4}.doc{color:var(--muted);font-size:12.5px;float:right}
table{width:100%;border-collapse:collapse;margin-top:8px}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
th{color:var(--muted);font-weight:500}code{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.note{color:var(--muted);font-size:12.5px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}
"""


def _finding_html(x: dict) -> str:
    """Um achado em HTML. Todo texto vem de dados do usuário, então passa por html.escape."""
    e = html.escape
    color = COLOR[x["severity"]]
    detail = f'<div class="d">{e(x["detail"])}</div>' if x["detail"] else ""
    action = f'<div class="a">Ação sugerida: {e(x["action"])}</div>' if x["action"] else ""
    return (f'<div class="f" style="border-left-color:{color}"><span class="doc">{e(x["doc"])}</span>'
            f'<div class="t"><span class="badge" style="background:{color}">{e(SEV_LABEL[x["severity"]])}</span>'
            f'{e(x["title"])}</div>{detail}{action}</div>')


def render_html(result: dict) -> str:
    e = html.escape
    items = "".join(_finding_html(x) for x in result["findings"]) or \
        '<p class="sub">Nenhuma divergência encontrada nas regras verificadas.</p>'
    rows = "".join(f'<tr><td>{e(f["doc"])}</td><td><code>{e(f["name"])}</code></td><td>{e(f["type"])}</td>'
                   f'<td>{e(str(f["producer"] or "-"))}</td><td><code>{e(f["sha256"])}</code></td></tr>'
                   for f in result["files"])
    table = ('<h3>Arquivos inspecionados</h3><table><tr><th>Documento</th><th>Arquivo</th><th>Tipo</th>'
             f'<th>Programa</th><th>SHA-256</th></tr>{rows}</table>') if rows else ""
    who = result["proponent"]
    col = COLOR.get(result["level"], "#8ba0b2")
    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>DocCheck - parecer</title><style>{CSS}</style></head><body><main>
<h1>DocCheck</h1><p class="sub">Parecer de conferência · {datetime.now():%d/%m/%Y %H:%M} · referência {e(result["reference_date"])}</p>
<p>Proponente: <b>{e(str(who.get("nome") or "-"))}</b> · CPF {e(str(who.get("cpf") or "-"))} · {e(", ".join(result["documents"]))}</p>
<div class="verdict" style="border-left-color:{col}"><b style="color:{col}">{e(result["verdict"])}</b><br>
<span class="sub">Nota de atenção {result["risk"]}/100 · {len(result["findings"])} ponto(s)</span></div>
{items}{table}<p class="note">{e(result["note"])}</p></main></body></html>"""
