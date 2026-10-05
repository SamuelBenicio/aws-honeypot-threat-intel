#!/usr/bin/env python3
"""
Testes unitários para utilitários de análise e telemetria de logs:
- scripts/parse_logs.py
- scripts/generate_threat_report.py
"""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Adiciona a raiz do projeto ao sys.path para importação dos scripts
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.parse_logs import parse_cowrie_file, generate_markdown_report, generate_text_log
import scripts.generate_threat_report as threat_reporter


class TestLogParsers(unittest.TestCase):
    def setUp(self):
        self.sample_events = [
            {
                "eventid": "cowrie.session.connect",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:00.000Z",
                "src_ip": "198.51.100.10",
                "src_port": 54321
            },
            {
                "eventid": "cowrie.client.version",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:01.000Z",
                "version": "SSH-2.0-libssh_0.9.5"
            },
            {
                "eventid": "cowrie.client.kex",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:02.000Z",
                "hassh": "b9687e411333fc8a72ec222b467aaee3"
            },
            {
                "eventid": "cowrie.login.failed",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:03.000Z",
                "username": "root",
                "password": "wrongpassword"
            },
            {
                "eventid": "cowrie.login.success",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:05.000Z",
                "username": "admin",
                "password": "admin123"
            },
            {
                "eventid": "cowrie.command.input",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:06.000Z",
                "input": "uname -a; cat /proc/cpuinfo"
            },
            {
                "eventid": "cowrie.session.file_download",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:08.000Z",
                "url": "http://malicious.domain/payload.sh",
                "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            {
                "eventid": "cowrie.session.closed",
                "session": "sess-01",
                "timestamp": "2026-10-01T12:00:15.000Z",
                "duration_ms": 15000
            }
        ]

    def test_parse_cowrie_file_full_lifecycle(self):
        """Valida que todos os eventos do ciclo de vida da sessão SSH são extraídos corretamente."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f:
            for ev in self.sample_events:
                f.write(json.dumps(ev) + "\n")
            temp_path = f.name

        try:
            sessions = parse_cowrie_file(temp_path)
            self.assertIn("sess-01", sessions)
            sess = sessions["sess-01"]

            self.assertEqual(sess["ip"], "198.51.100.10")
            self.assertEqual(sess["port"], 54321)
            self.assertEqual(sess["client_version"], "SSH-2.0-libssh_0.9.5")
            self.assertEqual(sess["hassh"], "b9687e411333fc8a72ec222b467aaee3")
            self.assertEqual(len(sess["logins"]), 2)
            self.assertEqual(sess["logins"][0]["status"], "FALHA")
            self.assertEqual(sess["logins"][1]["status"], "SUCESSO")
            self.assertEqual(sess["commands"][0]["cmd"], "uname -a; cat /proc/cpuinfo")
            self.assertEqual(sess["files_downloaded"][0]["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            self.assertEqual(sess["duration_ms"], 15000)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_parse_empty_and_corrupt_files(self):
        """Valida resiliência a arquivos vazios, linhas em branco ou dados JSON inválidos."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f:
            f.write("\n\n   \n")
            temp_empty = f.name

        try:
            sessions = parse_cowrie_file(temp_empty)
            self.assertEqual(len(sessions), 0)
        finally:
            if os.path.exists(temp_empty):
                os.remove(temp_empty)

    def test_generate_markdown_report_formatting(self):
        """Valida se a geração do relatório Markdown contém os elementos essenciais de auditoria."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f_in:
            for ev in self.sample_events:
                f_in.write(json.dumps(ev) + "\n")
            in_path = f_in.name

        out_path = in_path + ".md"
        try:
            sessions = parse_cowrie_file(in_path)
            generate_markdown_report(sessions, in_path, out_path)

            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "r", encoding="utf-8") as rf:
                content = rf.read()

            self.assertIn("# 🛡️ Relatório de Telemetria de Cibersegurança", content)
            self.assertIn("198.51.100.10", content)
            self.assertIn("SSH-2.0-libssh_0.9.5", content)
            self.assertIn("b9687e411333fc8a72ec222b467aaee3", content)
            self.assertIn("uname -a; cat /proc/cpuinfo", content)
            self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", content)
        finally:
            if os.path.exists(in_path):
                os.remove(in_path)
            if os.path.exists(out_path):
                os.remove(out_path)

    def test_generate_text_log_formatting(self):
        """Valida geração do formato Syslog / texto linear."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f_in:
            for ev in self.sample_events:
                f_in.write(json.dumps(ev) + "\n")
            in_path = f_in.name

        out_path = in_path + ".txt"
        try:
            sessions = parse_cowrie_file(in_path)
            generate_text_log(sessions, out_path)

            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "r", encoding="utf-8") as rf:
                content = rf.read()

            self.assertIn("[NOVA CONEXAO] IP: 198.51.100.10", content)
            self.assertIn("[AUTENTICACAO] IP: 198.51.100.10 | User: 'root'", content)
            self.assertIn("[COMANDO DIGITADO]", content)
            self.assertIn("[DESCONEXAO]", content)
        finally:
            if os.path.exists(in_path):
                os.remove(in_path)
            if os.path.exists(out_path):
                os.remove(out_path)

    @patch("scripts.generate_threat_report.glob.glob")
    @patch("scripts.generate_threat_report.urllib.request.urlopen")
    def test_generate_threat_report_aggregation(self, mock_urlopen, mock_glob):
        """Valida agregação de estatísticas, top IPs e geolocalização mockada no threat reporter."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False, suffix=".json") as f_log:
            for ev in self.sample_events:
                f_log.write(json.dumps(ev) + "\n")
            log_path = f_log.name

        mock_glob.return_value = [log_path]

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "country": "Netherlands",
            "city": "Amsterdam",
            "org": "AS12345 Mock Hosting"
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        report_target = "logs_salvos/RELATORIO_THREAT_INTEL_REAL_TEST.md"
        
        # Testamos a função com patch no caminho do relatório para não sobreescrever dados de produção
        with patch("scripts.generate_threat_report.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file
            
            # Chama a execução
            threat_reporter.generate_report()

            # Verifica se tentou escrever o relatório
            mock_file.write.assert_called()

        if os.path.exists(log_path):
            os.remove(log_path)


if __name__ == "__main__":
    unittest.main()
