"""Gera exemplos 100% FICTÍCIOS: duas fichas (uma coerente, uma com problemas) e arquivos sintéticos.

Os PDFs e a imagem são criados aqui só para ter metadados a inspecionar. Não imitam documentos reais:
o PDF diz "DOCUMENTO FICTICIO DE TESTE" e o arquivo JPEG contém apenas metadados, sem imagem.
"""
from __future__ import annotations

import json
import os
import struct
from typing import Dict, Optional

from .validators import make_cnh, make_cnpj, make_cpf


# ---- PDF mínimo, com metadados controlados ----------------------------------------------------------------------------
def _pdf_date(stamp: str) -> str:
    return f"D:{stamp}-03'00'"


def make_pdf(producer: str, created: str, modified: Optional[str] = None, edited_with: Optional[str] = None,
             creator: str = "Sistema Exemplo") -> bytes:
    """Cria um PDF de 1 página. Se 'edited_with' for dado, acrescenta uma revisão incremental feita por esse programa."""
    def info(prod, cdate, mdate):
        parts = f"/Producer ({prod}) /Creator ({creator}) /CreationDate ({_pdf_date(cdate)})"
        return f"<< {parts}" + (f" /ModDate ({_pdf_date(mdate)})" if mdate else "") + " >>"

    stream = b"BT /F1 16 Tf 60 780 Td (DOCUMENTO FICTICIO DE TESTE - SEM VALOR) Tj ET"
    bodies = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
              b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
              b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
              b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", info(producer, created, modified).encode()]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(bodies, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += (f"xref\n0 {len(bodies) + 1}\n0000000000 65535 f \n" + "".join(f"{o:010d} 00000 n \n" for o in offsets)).encode()
    out += f"trailer\n<< /Size {len(bodies) + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    if edited_with:
        off = len(out)
        out += b"6 0 obj\n" + info(edited_with, created, modified or created).encode() + b"\nendobj\n"
        xref2 = len(out)
        out += f"xref\n6 1\n{off:010d} 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev {xref} >>\nstartxref\n{xref2}\n%%EOF\n".encode()
    return bytes(out)


# ---- JPEG só com metadados EXIF ---------------------------------------------------------------------------------------------
def _tiff(ifd0: Dict[int, str], exif: Dict[int, str]) -> bytes:
    n0 = len(ifd0) + (1 if exif else 0)
    ifd0_len = 2 + 12 * n0 + 4
    exif_off = 8 + ifd0_len
    area = 8 + ifd0_len + ((2 + 12 * len(exif) + 4) if exif else 0)
    blob = bytearray()

    def entry(tag: int, text: str) -> bytes:
        raw = text.encode("latin-1") + b"\x00"
        if len(raw) <= 4:
            return struct.pack("<HHI4s", tag, 2, len(raw), raw.ljust(4, b"\x00"))
        offset = area + len(blob)
        blob.extend(raw)
        return struct.pack("<HHII", tag, 2, len(raw), offset)

    e0 = [entry(t, v) for t, v in sorted(ifd0.items())]
    if exif:
        e0.append(struct.pack("<HHII", 0x8769, 4, 1, exif_off))
    e0.sort(key=lambda e: struct.unpack("<H", e[:2])[0])
    ex = [entry(t, v) for t, v in sorted(exif.items())]
    tiff = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", len(e0)) + b"".join(e0) + b"\x00" * 4
    if exif:
        tiff += struct.pack("<H", len(ex)) + b"".join(ex) + b"\x00" * 4
    return tiff + bytes(blob)


def make_exif_jpeg(software: str, modified: str, original: str, make: str = "", model: str = "") -> bytes:
    ifd0 = {0x0131: software, 0x0132: modified}
    if make:
        ifd0[0x010F], ifd0[0x0110] = make, model
    tiff = _tiff(ifd0, {0x9003: original})
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", 8 + len(tiff)) + b"Exif\x00\x00" + tiff + b"\xff\xd9"


# ---- fichas -----------------------------------------------------------------------------------------------------------------------
NAME = "MARIA FERNANDA DE OLIVEIRA SOUZA"
CPF = make_cpf("390533447")
OUTRO_CPF = make_cpf("987654321")


def _proposta(renda: float) -> dict:
    return {"nome": NAME, "cpf": CPF, "data_nascimento": "12/04/1991", "renda_declarada": renda,
            "endereco": {"cep": "04000-000", "logradouro": "RUA EXEMPLO", "numero": "120"}}


def ficha_ok() -> dict:
    return {"data_referencia": "2026-10-21", "proposta": _proposta(5200.00), "documentos": {
        "cnh": {"nome": NAME, "cpf": CPF, "numero_registro": make_cnh("123456789"), "categoria": "B",
                "data_nascimento": "12/04/1991", "primeira_habilitacao": "10/06/2010", "data_emissao": "18/05/2022",
                "validade": "18/05/2032"},
        "comprovante_endereco": {"nome": NAME, "tipo": "conta de energia", "data_emissao": "28/09/2026", "cep": "04000-000",
                                 "logradouro": "RUA EXEMPLO", "numero": "120", "cidade": "SAO PAULO", "uf": "SP",
                                 "arquivo": "endereco_ok.pdf"},
        "comprovante_renda": {"tipo": "holerite", "nome": NAME, "cpf": CPF, "competencia": "09/2026",
                              "empregador": "EMPRESA EXEMPLO LTDA", "cnpj_empregador": make_cnpj("123456780001"),
                              "bruto": "5.200,00", "descontos": "1.148,00", "liquido": "4.052,00",
                              "arquivo": "holerite_ok.pdf"}}}


def ficha_divergente() -> dict:
    return {"data_referencia": "2026-10-21", "proposta": _proposta(8500.00), "documentos": {
        "cnh": {"nome": NAME, "cpf": OUTRO_CPF, "numero_registro": "12345678901", "categoria": "B",
                "data_nascimento": "12/04/1991", "primeira_habilitacao": "10/06/2010", "data_emissao": "18/05/2016",
                "validade": "15/03/2026"},
        "comprovante_endereco": {"nome": "CARLOS EDUARDO PEREIRA", "tipo": "conta de agua", "data_emissao": "10/04/2026",
                                 "cep": "01310-100", "logradouro": "AV EXEMPLO", "numero": "900", "cidade": "SAO PAULO",
                                 "uf": "SP", "arquivo": "endereco_editado.jpg"},
        "comprovante_renda": {"tipo": "holerite", "nome": NAME, "cpf": CPF, "competencia": "03/2026",
                              "empregador": "EMPRESA EXEMPLO LTDA", "cnpj_empregador": "12.345.678/0001-00",
                              "bruto": "5.200,00", "descontos": "1.148,00", "liquido": "4.400,00",
                              "arquivo": "holerite_editado.pdf"}}}


def write_samples(directory: str) -> list:
    os.makedirs(directory, exist_ok=True)
    files = {
        "holerite_ok.pdf": make_pdf("Sistema de Folha Exemplo 4.2", "20261001090000"),
        "endereco_ok.pdf": make_pdf("Portal da Concessionaria Exemplo", "20260929101500"),
        "holerite_editado.pdf": make_pdf("Sistema de Folha Exemplo 4.2", "20260201090000", "20260201090000",
                                         edited_with="Adobe Photoshop 25.1"),
        "endereco_editado.jpg": make_exif_jpeg("Adobe Photoshop 25.1", "2026:10:20 22:41:10", "2026:03:02 08:15:00"),
    }
    out = []
    for name, data in files.items():
        with open(os.path.join(directory, name), "wb") as f:
            f.write(data)
        out.append(name)
    for name, ficha in (("ficha_ok.json", ficha_ok()), ("ficha_divergente.json", ficha_divergente())):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
            json.dump(ficha, f, ensure_ascii=False, indent=2)
        out.append(name)
    return out


def inline_fichas() -> dict:
    """As duas fichas com os arquivos de exemplo embutidos (base64), para a interface web demonstrar a análise de arquivos."""
    import base64
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        write_samples(tmp)
        out = {}
        for key, ficha in (("coerente", ficha_ok()), ("com_problemas", ficha_divergente())):
            for doc in ficha["documentos"].values():
                name = doc.pop("arquivo", None)
                if name:
                    with open(os.path.join(tmp, name), "rb") as f:
                        doc["arquivo_b64"], doc["arquivo_nome"] = base64.b64encode(f.read()).decode(), name
            out[key] = ficha
        return out
