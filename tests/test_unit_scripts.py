"""
Testes Unitários para Scripts de Automação e Análise Forense:
- scripts/analyze_2days.py
- scripts/backfill_enrichment.py
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import scripts.analyze_2days as analyzer
import scripts.backfill_enrichment as backfill


class TestUnitScripts(unittest.TestCase):
    def setUp(self):
        self.sample_lines = [
            json.dumps({
                "eventid": "cowrie.session.connect",
                "session": "session-1",
                "timestamp": "2026-10-07T12:00:00Z",
                "src_ip": "198.51.100.1"
            }),
            json.dumps({
                "eventid": "cowrie.login.failed",
                "session": "session-1",
                "timestamp": "2026-10-07T12:00:01Z",
                "src_ip": "198.51.100.1",
                "username": "admin",
                "password": "wrongpassword"
            }),
            json.dumps({
                "eventid": "cowrie.login.success",
                "session": "session-1",
                "timestamp": "2026-10-07T12:00:02Z",
                "src_ip": "198.51.100.1",
                "username": "root",
                "password": "correctpassword"
            }),
            json.dumps({
                "eventid": "cowrie.command.input",
                "session": "session-1",
                "timestamp": "2026-10-07T12:00:03Z",
                "src_ip": "198.51.100.1",
                "input": "cat /etc/issue"
            }),
            json.dumps({
                "eventid": "cowrie.session.file_upload",
                "session": "session-1",
                "timestamp": "2026-10-07T12:00:04Z",
                "src_ip": "198.51.100.1",
                "filename": "exploit.sh",
                "shasum": "abcdef123456"
            }),
            # Evento do operador que deve ser filtrado
            json.dumps({
                "eventid": "cowrie.login.failed",
                "session": "session-operator",
                "timestamp": "2026-10-07T12:00:05Z",
                "src_ip": "187.15.86.243",
                "username": "operator_test",
                "password": "test"
            })
        ]

    # -------------------------------------------------------------------------
    # Testes do analyze_2days.py
    # -------------------------------------------------------------------------
    def test_analyze_load_events_from_files(self):
        """Valida que load_events_from_files lê corretamente e ignora linhas corrompidas"""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f:
            for l in self.sample_lines:
                f.write(l + "\n")
            f.write("CORRUPTED NOT JSON\n")
            temp_path = f.name

        try:
            events = analyzer.load_events_from_files([temp_path])
            self.assertEqual(len(events), len(self.sample_lines))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_analyze_filter_and_aggregate_metrics(self):
        """Valida a separação de tráfego malicioso e exclusão do IP do operador"""
        events = [json.loads(l) for l in self.sample_lines]
        metrics = analyzer.filter_and_aggregate_metrics(events, operator_ip="187.15.86.243")

        # Garante exclusão do IP do operador
        self.assertEqual(len(metrics["filtered_events"]), 5)
        for e in metrics["filtered_events"]:
            self.assertNotEqual(e.get("src_ip"), "187.15.86.243")

        # Valida contagens analíticas
        self.assertEqual(len(metrics["sessions"]), 1)
        self.assertEqual(len(metrics["logins"]), 2)
        self.assertEqual(len(metrics["success_logins"]), 1)
        self.assertEqual(len(metrics["failed_logins"]), 1)
        self.assertEqual(metrics["user_counts"]["root"], 1)
        self.assertEqual(metrics["password_counts"]["correctpassword"], 1)
        self.assertEqual(len(metrics["uploads"]), 1)
        self.assertEqual(metrics["uploads"][0]["filename"], "exploit.sh")
        self.assertEqual(len(metrics["cmds"]), 1)
        self.assertEqual(metrics["cmds"][0]["input"], "cat /etc/issue")

    @patch("urllib.request.urlopen")
    def test_analyze_fetch_geoip_metadata_success(self, mock_urlopen):
        """Valida consulta de geolocalização com mock de sucesso"""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "country": "Brazil",
            "city": "Campinas",
            "isp": "Telecom Provider",
            "as": "AS28573"
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = analyzer.fetch_geoip_metadata("198.51.100.1")
        self.assertEqual(res["country"], "Brazil")
        self.assertEqual(res["city"], "Campinas")
        self.assertEqual(res["isp"], "Telecom Provider")

    @patch("urllib.request.urlopen", side_effect=Exception("Timeout"))
    def test_analyze_fetch_geoip_metadata_failure(self, mock_urlopen):
        """Valida fallback limpo quando a requisição falha"""
        res = analyzer.fetch_geoip_metadata("198.51.100.2")
        self.assertEqual(res["country"], "N/A")
        self.assertEqual(res["city"], "N/A")

    @patch("scripts.analyze_2days.glob.glob")
    @patch("scripts.analyze_2days.fetch_geoip_metadata")
    def test_analyze_main_execution(self, mock_geo, mock_glob):
        """Valida execução completa da função main() do script analyze_2days.py"""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f:
            for l in self.sample_lines:
                f.write(l + "\n")
            temp_path = f.name

        mock_glob.return_value = [temp_path]
        mock_geo.return_value = {"country": "Brazil", "city": "Sao Paulo", "isp": "ISP", "as": "AS1"}

        try:
            # Executa main redirecionando stdout
            import io
            from contextlib import redirect_stdout
            f_out = io.StringIO()
            with redirect_stdout(f_out):
                analyzer.main()
            out = f_out.getvalue()
            self.assertIn("METRICAS GERAIS", out)
            self.assertIn("TOP 10 USUARIOS", out)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # -------------------------------------------------------------------------
    # Testes do backfill_enrichment.py
    # -------------------------------------------------------------------------
    def test_backfill_empty_directory_returns_empty(self):
        """Valida saída segura sem erros caso não existam arquivos de log brutos"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = backfill.run_mining(base_dir=tmp_dir)
            self.assertEqual(res, [])

    def test_backfill_mining_and_s3_upload(self):
        """Valida mineração de dados brutos e upload estruturado no bucket S3"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Cria arquivo de log com os dados de amostra
            log_dir = Path(tmp_dir) / "year=2026" / "month=10" / "day=07"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / "cowrie_test.json"

            with open(log_file, "w", encoding="utf-8") as f:
                for line in self.sample_lines:
                    f.write(line + "\n")

            mock_s3 = MagicMock()

            # Executa mineração direcionando para o diretório temporário
            records = backfill.run_mining(
                base_dir=tmp_dir,
                bucket_name="test-mock-bucket",
                s3_client=mock_s3
            )

            # Deve extrair os atacantes (2 IPs: 198.51.100.1 e 187.15.86.243)
            self.assertGreaterEqual(len(records), 1)

            # Valida chamada de upload no S3 com criptografia SSE-S3
            mock_s3.put_object.assert_called_once()
            call_kwargs = mock_s3.put_object.call_args[1]
            self.assertEqual(call_kwargs["Bucket"], "test-mock-bucket")
            self.assertEqual(call_kwargs["ServerSideEncryption"], "AES256")
            self.assertEqual(call_kwargs["ContentType"], "application/json")


if __name__ == "__main__":
    unittest.main()
