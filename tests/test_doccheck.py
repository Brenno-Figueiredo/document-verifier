import base64
import contextlib
import http.client
import io
import json
import os
import struct
import sys
import tempfile
import threading
import unittest
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from doccheck import forensics, report  # noqa: E402
from doccheck.cli import main  # noqa: E402
from doccheck.rules import run_check  # noqa: E402
from doccheck.samples import (OUTRO_CPF, CPF, NAME, ficha_divergente, ficha_ok, inline_fichas,  # noqa: E402
                              make_exif_jpeg, make_pdf, write_samples)
from doccheck.server import make_server  # noqa: E402
from doccheck.validators import (mask_cnh, mask_cpf, make_cnh, make_cnpj, make_cpf, name_similarity,  # noqa: E402
                                 parse_date, parse_money, parse_month, valid_cep, valid_cnh, valid_cnpj, valid_cpf)

TODAY = date(2026, 10, 21)


def codes(result):
    return {f["code"] for f in result["findings"]}


class ValidatorTests(unittest.TestCase):
    def test_cpf(self):
        self.assertTrue(valid_cpf("529.982.247-25"))
        self.assertFalse(valid_cpf("529.982.247-24"))
        self.assertFalse(valid_cpf("111.111.111-11"))
        self.assertFalse(valid_cpf("123"))
        self.assertTrue(valid_cpf(make_cpf("123456789")))

    def test_cnpj_including_alphanumeric(self):
        self.assertTrue(valid_cnpj("11.222.333/0001-81"))
        self.assertFalse(valid_cnpj("11.222.333/0001-82"))
        self.assertFalse(valid_cnpj("00.000.000/0000-00"))
        self.assertTrue(valid_cnpj(make_cnpj("12ABC34501DE")))

    def test_cnh_roundtrip_and_rejections(self):
        self.assertTrue(valid_cnh(make_cnh("987654321")))
        self.assertTrue(valid_cnh("02650306461"))
        self.assertFalse(valid_cnh("12345678901"))
        self.assertFalse(valid_cnh("00000000000"))

    def test_cep_dates_money(self):
        self.assertTrue(valid_cep("04000-000"))
        self.assertFalse(valid_cep("00000-000"))
        self.assertEqual(parse_date("21/10/2026"), date(2026, 10, 21))
        self.assertEqual(parse_date("2026-10-21"), date(2026, 10, 21))
        self.assertIsNone(parse_date("31/02/2026"))
        self.assertEqual(parse_month("09/2026"), date(2026, 9, 1))
        self.assertEqual(str(parse_money("R$ 4.500,00")), "4500.00")
        self.assertEqual(str(parse_money("4.500")), "4500")
        self.assertEqual(str(parse_money("4500.50")), "4500.50")
        self.assertIsNone(parse_money("abc"))

    def test_names(self):
        self.assertEqual(name_similarity("Maria de Oliveira", "MARIA OLIVEIRA"), 1.0)
        self.assertGreaterEqual(name_similarity("J. Silva", "João da Silva"), 0.92)
        self.assertLess(name_similarity("Maria Souza", "Carlos Pereira"), 0.75)
        self.assertEqual(name_similarity("", "x"), 0.0)

    def test_masks(self):
        self.assertEqual(mask_cpf("52998224725"), "***.982.247-**")
        self.assertEqual(mask_cnh("02650306461"), "*******6461")


class ForensicsTests(unittest.TestCase):
    def inspect(self, data, name="x.pdf"):
        return forensics.inspect(data, name, TODAY)

    def kinds(self, info):
        return {f.code for f in info["findings"]}

    def test_clean_pdf_has_no_findings(self):
        info = self.inspect(make_pdf("Sistema de Folha 1.0", "20261001090000"))
        self.assertEqual(info["findings"], [])
        self.assertEqual(info["type"], "pdf")

    def test_editor_and_incremental_update(self):
        info = self.inspect(make_pdf("Sistema 1.0", "20260201090000", edited_with="Adobe Photoshop 25"))
        self.assertTrue({"editor_detectado", "atualizacao_incremental"} <= self.kinds(info))
        self.assertEqual(info["meta"]["revisions"], 2)

    def test_modified_after_creation(self):
        info = self.inspect(make_pdf("Sistema 1.0", "20260901090000", "20261015090000"))
        self.assertIn("modificado_apos_criacao", self.kinds(info))

    def test_active_content_and_future_date(self):
        data = make_pdf("Sistema 1.0", "20271201090000") + b"\n/JavaScript (app.alert(1))\n"
        info = self.inspect(data)
        self.assertTrue({"conteudo_ativo", "data_futura"} <= self.kinds(info))

    def test_signed_pdf_revisions_are_not_flagged_as_tampering(self):
        data = make_pdf("Sistema 1.0", "20261001090000", edited_with="Sistema 1.1") + b"/ByteRange [0 1 2 3]"
        info = self.inspect(data)
        sev = {f.code: f.severity for f in info["findings"]}
        self.assertEqual(sev["atualizacao_incremental"], "info")

    def test_jpeg_exif(self):
        info = self.inspect(make_exif_jpeg("Adobe Photoshop 25", "2026:10:20 22:00:00", "2026:03:02 08:00:00"), "a.jpg")
        self.assertEqual(info["meta"]["software"], "Adobe Photoshop 25")
        self.assertTrue({"editor_detectado", "modificado_apos_criacao"} <= self.kinds(info))

    def test_camera_photo_is_clean(self):
        info = self.inspect(make_exif_jpeg("Camera 1.0", "2026:10:20 10:00:00", "2026:10:20 10:00:00", "Marca", "Modelo"), "a.jpg")
        self.assertEqual(info["findings"], [])
        self.assertEqual(info["meta"]["make"], "Marca")

    def test_image_without_metadata_and_png_text(self):
        self.assertIn("sem_metadados", self.kinds(self.inspect(b"\xff\xd8\xff\xd9", "a.jpg")))
        png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I4s", 17, b"tEXt") + b"Software\x00Canva 1.0" + b"\x00" * 4 \
            + struct.pack(">I4s", 0, b"IEND") + b"\x00" * 4
        info = self.inspect(png, "a.png")
        self.assertIn("editor_detectado", self.kinds(info))

    def test_extension_mismatch_and_unknown_type(self):
        self.assertIn("sem_metadados", self.kinds(self.inspect(b"MZ\x90\x00 programa", "nota.pdf")))
        self.assertEqual(self.inspect(b"texto qualquer", "a.txt")["type"], "outro")

    def test_hash_is_stable(self):
        self.assertEqual(forensics.sha256(b"abc"), forensics.sha256(b"abc"))
        self.assertNotEqual(forensics.sha256(b"abc"), forensics.sha256(b"abd"))

    def test_corrupted_files_do_not_crash(self):
        for blob in (b"%PDF-1.4 /Producer (", b"\xff\xd8\xff\xe1\x00\x05ab", b"\x89PNG\r\n\x1a\n\xff\xff\xff\xff"):
            self.assertIsInstance(self.inspect(blob, "x.bin"), dict)


class RulesTests(unittest.TestCase):
    def check(self, ficha, **kw):
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
        return run_check(ficha, base_dir=base, allow_paths=True, **kw)

    def setUp(self):
        self.samples = tempfile.mkdtemp()
        write_samples(self.samples)

    def test_coherent_ficha_has_no_findings(self):
        r = run_check(ficha_ok(), base_dir=self.samples, allow_paths=True)
        self.assertEqual((r["level"], r["risk"], r["findings"]), ("ok", 0, []))

    def test_problem_ficha_hits_the_expected_rules(self):
        r = run_check(ficha_divergente(), base_dir=self.samples, allow_paths=True)
        expected = {"cpf_diverge", "cnh_vencida", "cnh_numero", "cnpj_invalido", "conta_nao_fecha", "renda_acima",
                    "comprovante_antigo", "nome_diverge", "cep_diverge", "editor_detectado", "atualizacao_incremental",
                    "arquivo_criado_antes", "modificado_apos_criacao"}
        self.assertTrue(expected <= codes(r), expected - codes(r))
        self.assertEqual(r["level"], "critical")
        self.assertEqual(r["risk"], 100)

    def test_cpf_mismatch_is_critical_and_masked(self):
        f = ficha_ok()
        f["documentos"]["cnh"]["cpf"] = OUTRO_CPF
        r = run_check(f)
        item = next(x for x in r["findings"] if x["code"] == "cpf_diverge")
        self.assertEqual(item["severity"], "critical")
        self.assertNotIn(CPF, json.dumps(r))
        self.assertNotIn(OUTRO_CPF, json.dumps(r))

    def test_birthdate_mismatch(self):
        f = ficha_ok()
        f["documentos"]["cnh"]["data_nascimento"] = "13/04/1991"
        self.assertIn("nascimento_diverge", codes(run_check(f)))

    def test_name_variants(self):
        f = ficha_ok()
        f["documentos"]["comprovante_renda"]["nome"] = "MARIA FERNANDA OLIVEIRA SOUZA"
        self.assertEqual(codes(run_check(f)), set())               # sem partícula: mesmo nome
        f["documentos"]["comprovante_renda"]["nome"] = "MARIA FERNANDA DE OLIVEIRA SOUSA"
        self.assertEqual(codes(run_check(f)), {"nome_similar"})    # troca de letra: só um aviso leve
        f["documentos"]["comprovante_renda"]["nome"] = "ANA PAULA LIMA"
        self.assertIn("nome_diverge", codes(run_check(f)))

    def test_payslip_arithmetic_tolerance(self):
        f = ficha_ok()
        f["documentos"]["comprovante_renda"]["liquido"] = "4.052,03"
        self.assertNotIn("conta_nao_fecha", codes(run_check(f)))     # dentro da tolerância de R$ 0,05
        f["documentos"]["comprovante_renda"]["liquido"] = "4.100,00"
        self.assertIn("conta_nao_fecha", codes(run_check(f)))

    def test_declared_income_margin(self):
        f = ficha_ok()
        f["proposta"]["renda_declarada"] = 5400
        self.assertNotIn("renda_acima", codes(run_check(f)))
        f["proposta"]["renda_declarada"] = 6000
        self.assertIn("renda_acima", codes(run_check(f)))

    def test_cnh_dates_and_age(self):
        f = ficha_ok()
        f["documentos"]["cnh"]["primeira_habilitacao"] = "10/06/2008"     # tinha 17 anos
        self.assertIn("datas_incoerentes", codes(run_check(f)))
        f = ficha_ok()
        f["documentos"]["cnh"]["validade"] = "01/01/2020"                  # antes da emissão e vencida
        r = codes(run_check(f))
        self.assertTrue({"datas_incoerentes", "cnh_vencida"} <= r)

    def test_reference_date_controls_recency(self):
        r = run_check(ficha_ok(), config={})
        f = ficha_ok()
        f["data_referencia"] = "2027-06-01"
        self.assertEqual(r["findings"], [])
        self.assertIn("comprovante_antigo", codes(run_check(f)))

    def test_same_file_for_two_documents(self):
        f = ficha_ok()
        blob = base64.b64encode(make_pdf("Sistema 1.0", "20261001090000")).decode()
        for k in ("comprovante_endereco", "comprovante_renda"):
            f["documentos"][k].pop("arquivo")
            f["documentos"][k]["arquivo_b64"] = blob
        self.assertIn("arquivo_duplicado", codes(run_check(f)))

    def test_file_paths_are_ignored_unless_allowed(self):
        f = ficha_ok()
        f["documentos"]["cnh"]["arquivo"] = "/etc/passwd"
        r = run_check(f, allow_paths=False)
        self.assertEqual(r["files"], [])                                # o servidor nunca lê caminhos
        self.assertNotIn("passwd", json.dumps(r))

    def test_invalid_base64_is_reported(self):
        f = ficha_ok()
        f["documentos"]["cnh"]["arquivo_b64"] = "isso não é base64!!"
        self.assertIn("sem_metadados", codes(run_check(f)))

    def test_unknown_sections_and_empty_input(self):
        r = run_check({"documentos": {"passaporte": {"nome": "X"}}})
        self.assertEqual((r["level"], r["documents"]), ("ok", []))
        self.assertEqual(run_check({})["findings"], [])


class ReportTests(unittest.TestCase):
    def test_html_escapes_everything(self):
        f = ficha_ok()
        f["proposta"]["nome"] = "<script>alert(1)</script>"
        f["documentos"]["comprovante_renda"]["nome"] = "<img src=x onerror=alert(1)>"
        doc = report.render_html(run_check(f))
        self.assertNotIn("<script>alert", doc)
        self.assertNotIn("<img src=x", doc)
        self.assertIn("&lt;img", doc)

    def test_text_report_has_verdict_and_note(self):
        text = report.render_text(run_check(ficha_divergente()))
        self.assertIn("DIVERGÊNCIAS GRAVES", text)
        self.assertIn("NÃO prova", text)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def post(self, path, obj, ctype="application/json", headers=None):
        h = {"Content-Type": ctype, **(headers or {})}
        return self.request("POST", path, json.dumps(obj).encode(), h)

    def test_page_and_security_headers(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"DocCheck", body)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_check_with_inline_sample_files(self):
        status, _, body = self.post("/api/check", inline_fichas()["com_problemas"])
        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(result["level"], "critical")
        self.assertTrue(result["files"])                                # os arquivos embutidos foram inspecionados

    def test_coherent_sample_is_clean(self):
        _, _, body = self.post("/api/check", inline_fichas()["coerente"])
        self.assertEqual(json.loads(body)["level"], "ok")

    def test_live_validation_endpoint(self):
        _, _, body = self.post("/api/validate", {"cpf": "529.982.247-25", "cnpj": "11.222.333/0001-82", "x": "1"})
        self.assertEqual(json.loads(body), {"cpf": True, "cnpj": False})

    def test_rejects_foreign_host_header(self):                          # DNS rebinding
        status, _, _ = self.request("GET", "/", headers={"Host": "evil.example.com"})
        self.assertEqual(status, 403)
        status, _, _ = self.post("/api/check", {}, headers={"Host": "evil.example.com"})
        self.assertEqual(status, 403)

    def test_requires_json_content_type(self):                           # formulário de outro site (CSRF)
        status, _, _ = self.post("/api/check", {}, ctype="text/plain")
        self.assertEqual(status, 415)

    def test_bad_inputs(self):
        self.assertEqual(self.request("POST", "/api/check", b"{nao json", {"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.request("POST", "/api/check", b"[1,2]", {"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.request("GET", "/api/nao-existe")[0], 404)

    def test_server_does_not_read_paths(self):
        f = ficha_ok()
        f["documentos"]["cnh"]["arquivo"] = "/etc/passwd"
        _, _, body = self.post("/api/check", f)
        self.assertEqual(json.loads(body)["files"], [])


class CLITests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(argv))
        return code, out.getvalue()

    def test_check_exit_codes_and_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            write_samples(d)
            code, out = self.run_cli("check", os.path.join(d, "ficha_ok.json"), "--no-color")
            self.assertEqual(code, 0)
            html = os.path.join(d, "p.html")
            code, out = self.run_cli("check", os.path.join(d, "ficha_divergente.json"), "--html", html,
                                     "--json", os.path.join(d, "p.json"), "--no-color")
            self.assertEqual(code, 1)
            self.assertGreater(os.path.getsize(html), 500)
            self.assertNotIn(CPF, out)

    def test_validate_and_forensics(self):
        self.assertEqual(self.run_cli("validate", "cpf", "529.982.247-25")[0], 0)
        self.assertEqual(self.run_cli("validate", "cpf", "111.111.111-11")[0], 1)
        with tempfile.TemporaryDirectory() as d:
            write_samples(d)
            code, out = self.run_cli("forensics", os.path.join(d, "holerite_editado.pdf"))
            self.assertEqual(code, 1)
            self.assertIn("photoshop", out.lower())

    def test_bad_ficha_returns_2(self):
        self.assertEqual(self.run_cli("check", "/nao/existe.json")[0], 2)


if __name__ == "__main__":
    unittest.main()
