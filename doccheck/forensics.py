"""Análise forense básica de ARQUIVOS (PDF, JPEG, PNG): metadados e sinais de edição. Nada é executado.

Metadados são pistas, não provas: um documento legítimo pode ter sido reexportado, e um editor hábil
pode limpar os rastros. Por isso cada sinal pede revisão humana em vez de condenar o documento.
"""
from __future__ import annotations

import hashlib
import re
import struct
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from .findings import Finding

EDITORS = ("photoshop", "illustrator", "indesign", "canva", "gimp", "paint.net", "pixlr", "picsart", "snapseed",
           "affinity", "coreldraw", "inkscape", "ilovepdf", "smallpdf", "sejda", "pdfescape", "pdf24", "lightroom")
OFFICE = ("microsoft word", "libreoffice", "openoffice", "wps office", "microsoft excel")
SLACK = timedelta(seconds=60)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_type(data: bytes) -> str:
    if data[:1024].find(b"%PDF-") != -1:
        return "pdf"
    if data.startswith(b"\xff\xd8"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    return "outro"


def _editor_in(text: str) -> Optional[str]:
    low = text.lower()
    return next((e for e in EDITORS if e in low), None)


# ---- PDF ---------------------------------------------------------------------------------------------
def _pdf_values(data: bytes, key: str) -> List[str]:
    out = []
    for m in re.finditer(rb"/" + key.encode() + rb"\s*\(((?:\\.|[^\\)])*)\)", data, re.S):
        raw = re.sub(rb"\\(.)", rb"\1", m.group(1))
        out.append(raw[2:].decode("utf-16-be", "replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin-1"))
    for m in re.finditer(rb"/" + key.encode() + rb"\s*<([0-9A-Fa-f\s]+)>", data):
        raw = bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode())
        out.append(raw[2:].decode("utf-16-be", "replace") if raw.startswith(b"\xfe\xff") else raw.decode("latin-1"))
    return out


def _pdf_date(text: str) -> Optional[datetime]:
    m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([Z+\-])(\d{2})?'?(\d{2})?'?)?", text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, sign, oh, om = m.groups()
    try:
        dt = datetime(int(y), int(mo or 1), int(d or 1), int(h or 0), int(mi or 0), int(s or 0))
    except ValueError:
        return None
    off = timedelta(hours=int(oh or 0), minutes=int(om or 0)) * (-1 if sign == "-" else 1)
    return dt.replace(tzinfo=timezone(off if sign in ("+", "-") else timedelta(0)))


def _xmp(data: bytes, tag: str) -> Optional[str]:
    m = re.search(rb"<" + tag.encode() + rb">([^<]{1,200})</" + tag.encode() + rb">", data)
    return m.group(1).decode("utf-8", "replace") if m else None


def _iso(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def analyze_pdf(data: bytes, today: date) -> Tuple[Dict, List[Finding]]:
    producers = _pdf_values(data, "Producer") + [v for v in [_xmp(data, "pdf:Producer")] if v]
    creators = _pdf_values(data, "Creator") + [v for v in [_xmp(data, "xmp:CreatorTool")] if v]
    created = next(iter([d for d in (_pdf_date(v) for v in reversed(_pdf_values(data, "CreationDate"))) if d]), None) \
        or _iso(_xmp(data, "xmp:CreateDate"))
    modified = next(iter([d for d in (_pdf_date(v) for v in reversed(_pdf_values(data, "ModDate"))) if d]), None) \
        or _iso(_xmp(data, "xmp:ModifyDate"))
    eof, signed = len(re.findall(rb"%%EOF", data)), b"/ByteRange" in data
    meta = {"producer": producers[-1] if producers else None, "creator": creators[-1] if creators else None,
            "created": created.isoformat() if created else None, "modified": modified.isoformat() if modified else None,
            "revisions": eof, "pages": len(re.findall(rb"/Type\s*/Page\b", data)), "signed": signed}
    f: List[Finding] = []

    tools = " | ".join(dict.fromkeys(producers + creators))
    editor = _editor_in(tools)
    if editor:
        f.append(Finding("high", "editor_detectado", f"PDF passou por um editor ({editor})",
                         f"Programa registrado nos metadados: {tools[:120]}. Documentos emitidos por bancos e empresas "
                         "costumam sair de sistemas, não de editores de imagem ou de PDF online."))
    elif any(o in tools.lower() for o in OFFICE):
        f.append(Finding("low", "editor_detectado", "PDF gerado em editor de texto",
                         f"Programa nos metadados: {tools[:120]}. Pode ser normal em declarações simples."))
    if created and modified and modified - created > SLACK:
        f.append(Finding("medium", "modificado_apos_criacao", "Arquivo modificado depois de criado",
                         f"Criado em {created:%d/%m/%Y %H:%M} e modificado em {modified:%d/%m/%Y %H:%M}."))
    if eof >= 2:
        if signed:
            f.append(Finding("info", "atualizacao_incremental", "PDF com assinatura digital e revisões",
                             "Revisões são esperadas em PDFs assinados. Valide a assinatura no leitor."))
        else:
            extra = f" Produtores distintos: {' / '.join(dict.fromkeys(producers))}." if len(set(producers)) > 1 else ""
            f.append(Finding("medium", "atualizacao_incremental", f"PDF alterado depois de gerado ({eof} revisões)",
                             "O arquivo contém atualizações incrementais, o jeito como editores acrescentam mudanças "
                             "sem reescrever o original." + extra))
    if re.search(rb"/(JS|JavaScript|Launch)\b", data):
        f.append(Finding("high", "conteudo_ativo", "PDF com JavaScript ou ação de execução",
                         "Documentos de comprovação não precisam executar código. Trate o arquivo como suspeito."))
    if b"/EmbeddedFile" in data:
        f.append(Finding("medium", "conteudo_ativo", "PDF com arquivo embutido",
                         "Há outro arquivo escondido dentro do PDF."))
    if b"/Encrypt" in data:
        f.append(Finding("low", "sem_metadados", "PDF criptografado", "Não foi possível inspecionar tudo."))
    elif not (producers or creators or created):
        f.append(Finding("low", "sem_metadados", "PDF sem metadados", "Não há programa gerador nem datas registradas."))
    for label, dt in (("criação", created), ("modificação", modified)):
        if dt and dt.date() > today:
            f.append(Finding("medium", "data_futura", f"Data de {label} do arquivo no futuro",
                             f"{dt:%d/%m/%Y}, depois da data de referência ({today:%d/%m/%Y})."))
    return meta, f


# ---- imagens -------------------------------------------------------------------------------------------
def _parse_tiff(buf: bytes) -> Dict:
    end = "<" if buf[:2] == b"II" else ">"
    out: Dict = {}

    def ifd(offset: int, wanted: Dict[int, str]):
        n = struct.unpack(end + "H", buf[offset:offset + 2])[0]
        for i in range(min(n, 64)):
            e = offset + 2 + 12 * i
            tag, typ, cnt = struct.unpack(end + "HHI", buf[e:e + 8])
            raw = buf[e + 8:e + 12]
            if typ == 2 and tag in wanted:
                pos = struct.unpack(end + "I", raw)[0] if cnt > 4 else e + 8
                out[wanted[tag]] = buf[pos:pos + cnt].split(b"\x00")[0].decode("latin-1").strip()
            elif typ == 4 and tag in (0x8769, 0x8825):
                yield tag, struct.unpack(end + "I", raw)[0]

    try:
        first = struct.unpack(end + "I", buf[4:8])[0]
        for tag, off in ifd(first, {0x010F: "make", 0x0110: "model", 0x0131: "software", 0x0132: "datetime"}):
            if tag == 0x8769:
                list(ifd(off, {0x9003: "original", 0x9004: "digitized"}))
            else:
                out["gps"] = True
    except (struct.error, IndexError):
        pass
    return out


def _jpeg_exif(data: bytes) -> Optional[Dict]:
    i = 2
    while i + 4 <= len(data) and data[i] == 0xFF:
        marker, seglen = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker in (0xD9, 0xDA) or seglen < 2:
            return None
        seg = data[i + 4:i + 2 + seglen]
        if marker == 0xE1 and seg.startswith(b"Exif\x00\x00"):
            return _parse_tiff(seg[6:])
        i += 2 + seglen
    return None


def _png_text(data: bytes) -> Dict:
    out, i = {}, 8
    while i + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[i:i + 8])
        body = data[i + 8:i + 8 + length]
        if kind == b"tEXt" and b"\x00" in body:
            k, v = body.split(b"\x00", 1)
            out[k.decode("latin-1")] = v.decode("latin-1")
        if kind == b"IEND":
            break
        i += 12 + length
    return out


def _exif_dt(text: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.strptime(text or "", "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None


def analyze_image(data: bytes, kind: str, today: date) -> Tuple[Dict, List[Finding]]:
    f: List[Finding] = []
    if kind == "jpeg":
        tags = _jpeg_exif(data)
        meta = {"software": (tags or {}).get("software"), "make": (tags or {}).get("make"),
                "model": (tags or {}).get("model"), "modified": (tags or {}).get("datetime"),
                "created": (tags or {}).get("original"), "gps": bool((tags or {}).get("gps"))}
        has_meta = tags is not None and any(tags.values())
    else:
        txt = _png_text(data)
        meta = {"software": txt.get("Software"), "created": txt.get("Creation Time"), "modified": None,
                "make": None, "model": None, "gps": False}
        has_meta = bool(txt)
    editor = _editor_in(meta.get("software") or "")
    if editor:
        f.append(Finding("high", "editor_detectado", f"Imagem salva por um editor ({editor})",
                         f"Programa nos metadados: {meta['software']}. Foto de documento costuma sair direto da câmera "
                         "ou do scanner."))
    if not has_meta:
        f.append(Finding("low", "sem_metadados", "Imagem sem metadados",
                         "Normal em prints e imagens reenviadas por aplicativos de mensagem, mas impede a conferência."))
    a, b = _exif_dt(meta.get("created")), _exif_dt(meta.get("modified"))
    if a and b and abs(b - a) > SLACK:
        f.append(Finding("medium", "modificado_apos_criacao", "Data de captura diferente da data de modificação",
                         f"Capturada em {a:%d/%m/%Y %H:%M} e modificada em {b:%d/%m/%Y %H:%M}."))
    for label, dt in (("captura", a), ("modificação", b)):
        if dt and dt.date() > today:
            f.append(Finding("medium", "data_futura", f"Data de {label} da imagem no futuro", f"{dt:%d/%m/%Y}."))
    return meta, f


# ---- entrada principal -----------------------------------------------------------------------------------
def inspect(data: bytes, name: str, today: Optional[date] = None) -> Dict:
    today = today or date.today()
    kind = detect_type(data)
    result = {"name": name, "size": len(data), "sha256": sha256(data), "type": kind, "meta": {}, "findings": []}
    f: List[Finding] = []
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    expected = {"pdf": "pdf", "jpg": "jpeg", "jpeg": "jpeg", "png": "png"}.get(ext)
    if expected and expected != kind:
        f.append(Finding("medium", "sem_metadados", "Extensão não confere com o conteúdo",
                         f"O arquivo se chama .{ext}, mas o conteúdo é {kind}."))
    if kind == "pdf":
        result["meta"], more = analyze_pdf(data, today)
        f += more
    elif kind in ("jpeg", "png"):
        result["meta"], more = analyze_image(data, kind, today)
        f += more
    else:
        f.append(Finding("low", "sem_metadados", "Tipo de arquivo não analisado",
                         "Só PDF, JPEG e PNG são inspecionados. Peça o documento nesses formatos."))
    result["findings"] = f
    return result
