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

    # -------------------------------------------------------------------------
    # Testes do parse_logs.py
    # -------------------------------------------------------------------------
    def test_parse_logs_full_cycle(self):
        """Valida parsing de sessões e geração de relatórios Markdown e Syslog"""
        import scripts.parse_logs as parser

        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_json = Path(tmp_dir) / "test_session.json"
            sample_md = Path(tmp_dir) / "test_session.md"
            sample_txt = Path(tmp_dir) / "test_session.txt"

            events = [
                {"session": "s1", "eventid": "cowrie.session.connect", "timestamp": "2026-10-07T10:00:00Z", "src_ip": "198.51.100.5", "src_port": 2222},
                {"session": "s1", "eventid": "cowrie.client.version", "version": "SSH-2.0-OpenSSH_8.0"},
                {"session": "s1", "eventid": "cowrie.client.kex", "hassh": "abc123hassh"},
                {"session": "s1", "eventid": "cowrie.login.success", "username": "root", "password": "toor", "timestamp": "2026-10-07T10:00:01Z"},
                {"session": "s1", "eventid": "cowrie.command.input", "input": "id", "timestamp": "2026-10-07T10:00:02Z"},
                {"session": "s1", "eventid": "cowrie.session.file_download", "shasum": "sha256fake", "url": "http://evil/a", "timestamp": "2026-10-07T10:00:03Z"},
                {"session": "s1", "eventid": "cowrie.session.closed", "duration": 12.5, "timestamp": "2026-10-07T10:00:12Z"}
            ]

            with open(sample_json, "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")

            sessions = parser.parse_cowrie_file(str(sample_json))
            self.assertIn("s1", sessions)
            self.assertEqual(sessions["s1"]["ip"], "198.51.100.5")
            self.assertEqual(len(sessions["s1"]["logins"]), 1)
            self.assertEqual(len(sessions["s1"]["commands"]), 1)

            parser.generate_markdown_report(sessions, str(sample_json), str(sample_md))
            self.assertTrue(sample_md.exists())
            md_content = sample_md.read_text(encoding="utf-8")
            self.assertIn("198.51.100.5", md_content)
            self.assertIn("root", md_content)

            parser.generate_text_log(sessions, str(sample_txt))
            self.assertTrue(sample_txt.exists())
            txt_content = sample_txt.read_text(encoding="utf-8")
            self.assertIn("NOVA CONEXAO", txt_content)
            self.assertIn("COMANDO DIGITADO", txt_content)

    # -------------------------------------------------------------------------
    # Testes do generate_threat_report.py
    # -------------------------------------------------------------------------
    @patch("urllib.request.urlopen")
    def test_generate_threat_report_flow(self, mock_urlopen):
        """Valida geracao do relatorio executivo de ameacas"""
        import scripts.generate_threat_report as rep_gen

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "country": "Germany",
            "city": "Frankfurt",
            "org": "Hosting GmbH"
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmp_dir:
            logs_dir = Path(tmp_dir) / "logs_salvos" / "year=2026" / "month=10" / "day=01"
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / "cowrie_rep_test.json"

            events = [
                {"eventid": "cowrie.login.success", "src_ip": "198.51.100.8", "username": "root", "password": "pwd"},
                {"eventid": "cowrie.command.input", "src_ip": "198.51.100.8", "input": "uname -a"},
            ]
            with open(log_file, "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")

            with patch("scripts.generate_threat_report.glob.glob", return_value=[str(log_file)]):
                orig_path = Path("logs_salvos/RELATORIO_THREAT_INTEL_REAL.md")
                orig_content = orig_path.read_text(encoding="utf-8") if orig_path.exists() else None
                try:
                    Path("logs_salvos").mkdir(exist_ok=True)
                    rep_gen.generate_report()
                    self.assertTrue(orig_path.exists())
                finally:
                    if orig_content is not None:
                        orig_path.write_text(orig_content, encoding="utf-8")
                    elif orig_path.exists():
                        orig_path.unlink()

    @patch("urllib.request.urlopen", side_effect=Exception("GeoIP Down"))
    def test_generate_threat_report_corrupted_lines_and_geo_failure(self, mock_urlopen):
        """Valida resiliencia do generate_threat_report contra linhas JSON corrompidas e falha de GeoIP."""
        import scripts.generate_threat_report as rep_gen

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "corrupted.json"
            log_file.write_text(
                "\nNOT_VALID_JSON\n" + json.dumps({"eventid": "cowrie.login.failed", "src_ip": "198.51.100.99", "username": "u", "password": "p"}) + "\n",
                encoding="utf-8"
            )
            with patch("scripts.generate_threat_report.glob.glob", return_value=[str(log_file)]):
                orig_path = Path("logs_salvos/RELATORIO_THREAT_INTEL_REAL.md")
                orig_content = orig_path.read_text(encoding="utf-8") if orig_path.exists() else None
                try:
                    Path("logs_salvos").mkdir(exist_ok=True)
                    rep_gen.generate_report()
                    content = orig_path.read_text(encoding="utf-8")
                    self.assertIn("198.51.100.99", content)
                    self.assertIn("Desconhecido", content)
                finally:
                    if orig_content is not None:
                        orig_path.write_text(orig_content, encoding="utf-8")
                    elif orig_path.exists():
                        orig_path.unlink()

    def test_parse_logs_blank_lines_and_duration_ms(self):
        """Valida linhas em branco e formatacao de duration_ms no parse_logs.py."""
        import scripts.parse_logs as parser

        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_json = Path(tmp_dir) / "s2.json"
            sample_md = Path(tmp_dir) / "s2.md"
            sample_txt = Path(tmp_dir) / "s2.txt"

            sample_json.write_text(
                "\n"
                + json.dumps({"session": "s2", "eventid": "cowrie.session.connect", "timestamp": "2026-10-07T10:00:00Z", "src_ip": "198.51.100.6", "src_port": 2222}) + "\n"
                + json.dumps({"session": "s2", "eventid": "cowrie.session.closed", "timestamp": "2026-10-07T10:00:05Z", "duration_ms": 5000}) + "\n",
                encoding="utf-8"
            )
            sessions = parser.parse_cowrie_file(str(sample_json))
            parser.generate_markdown_report(sessions, str(sample_json), str(sample_md))
            parser.generate_text_log(sessions, str(sample_txt))

            self.assertIn("5.00s", sample_md.read_text(encoding="utf-8"))
            self.assertIn("[DESCONEXAO]", sample_txt.read_text(encoding="utf-8"))

    def test_backfill_default_args_with_mocked_boto3(self):
        """Valida caminho de argumentos padrao (base_dir=None, bucket_name=None, s3_client=None) em backfill_enrichment.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_file = Path(tmp_dir) / "c.json"
            sample_file.write_text(self.sample_lines[0] + "\n\n", encoding="utf-8")
            with patch.object(backfill.Path, "glob", return_value=[sample_file]), \
                 patch.object(backfill.boto3, "client") as mock_boto_client, \
                 patch.object(backfill.handler, "get_geoip_info", return_value={
                     "country_code": "BR", "country_name": "Brazil", "city": "SP",
                     "latitude": 0.0, "longitude": 0.0, "isp": "ISP"
                 }):
                mock_s3 = MagicMock()
                mock_boto_client.return_value = mock_s3
                res = backfill.run_mining(base_dir=None, bucket_name=None, s3_client=None)
                self.assertEqual(len(res), 1)
                mock_boto_client.assert_called_once_with("s3", region_name="us-east-1")

    # -------------------------------------------------------------------------
    # Testes do simulate_adversary.py
    # -------------------------------------------------------------------------
    @patch("scripts.simulate_adversary.time.sleep")
    @patch("scripts.simulate_adversary.paramiko.SSHClient")
    def test_simulate_adversary_full_flow_and_exceptions(self, mock_ssh_cls, mock_sleep):
        """Valida todos os ramos de simulate_adversary.py (AuthException, erro de rede, login aceito e shell)."""
        import scripts.simulate_adversary as sim

        # Configura clientes SSH simulados para as 6 tentativas de brute-force + 1 tentativa de sucesso
        clients = []
        for i in range(len(sim.FAILED_CREDENTIALS)):
            c = MagicMock()
            if i == 0:
                c.connect.side_effect = sim.paramiko.AuthenticationException("Auth failed")
            elif i == 1:
                c.connect.side_effect = RuntimeError("Connection reset")
            else:
                # Simula login inesperadamente aceito na fase 1
                c.connect.return_value = None
            clients.append(c)

        # Cliente da Fase 2 (sucesso com invoke_shell)
        c_success = MagicMock()
        mock_chan = MagicMock()
        c_success.invoke_shell.return_value = mock_chan
        clients.append(c_success)

        mock_ssh_cls.side_effect = clients
        sim.run_adversary_simulation()

        self.assertEqual(mock_chan.send.call_count, len(sim.COMMANDS_TO_RUN))
        c_success.close.assert_called_once()

        # Testa tambem o ramo de excecao na Fase 2 (sessao interativa falha)
        clients_fail_phase2 = [MagicMock() for _ in range(len(sim.FAILED_CREDENTIALS))]
        c_fail2 = MagicMock()
        c_fail2.connect.side_effect = RuntimeError("Interactive session timeout")
        clients_fail_phase2.append(c_fail2)

        mock_ssh_cls.side_effect = clients_fail_phase2
        sim.run_adversary_simulation()

    # -------------------------------------------------------------------------
    # Testes do test_lambda_local.py
    # -------------------------------------------------------------------------
    def test_lambda_local_script_execution(self):
        """Valida execucao de scripts/test_lambda_local.py com e sem arquivos de amostra."""
        import scripts.test_lambda_local as tll

        # 1. Caminho normal com logs reais (ou mock de glob)
        with patch.object(tll.handler, "get_geoip_info", return_value={
            "country_code": "US", "country_name": "United States", "city": "NYC",
            "latitude": 40.7, "longitude": -74.0
        }):
            tll.test_local_enrichment()

        # 2. Caminho quando nenhum arquivo JSON e encontrado
        with patch.object(tll.Path, "glob", return_value=[]):
            tll.test_local_enrichment()

    # -------------------------------------------------------------------------
    # Testes do check_pipeline_health.py
    # -------------------------------------------------------------------------
    @patch("scripts.check_pipeline_health.time.sleep", return_value=None)
    @patch("scripts.check_pipeline_health.boto3.client")
    def test_check_pipeline_health_full_success(self, mock_boto_client, mock_sleep):
        """Valida fluxo completo de sucesso de check_pipeline_health em todas as camadas."""
        import scripts.check_pipeline_health as cph

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "070443470233", "Arn": "arn:aws:iam::070443470233:user/admin"
        }

        mock_s3 = MagicMock()
        mock_s3.list_objects_v2.side_effect = [{"KeyCount": 10}, {"KeyCount": 5}]

        mock_lambda = MagicMock()
        mock_lambda.get_function.return_value = {
            "Configuration": {"Runtime": "python3.12", "MemorySize": 128, "Timeout": 120}
        }

        mock_athena = MagicMock()
        mock_athena.get_work_group.return_value = {
            "WorkGroup": {"State": "ENABLED", "Configuration": {"BytesScannedCutoffPerQuery": 104857600}}
        }

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"State": {"Name": "running"}, "PublicIpAddress": "54.210.1.2"}]}]
        }

        mock_ssm = MagicMock()
        mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"PingStatus": "Online"}]
        }
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-12345"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Success",
            "StandardOutputContent": "Running=true\nSTATE_POS=161\nINODE=12345\nTOTAL_LINES=161\n"
        }

        def client_dispatcher(service_name, **kwargs):
            if service_name == "sts":
                return mock_sts
            elif service_name == "s3":
                return mock_s3
            elif service_name == "lambda":
                return mock_lambda
            elif service_name == "athena":
                return mock_athena
            elif service_name == "ec2":
                return mock_ec2
            elif service_name == "ssm":
                return mock_ssm
            return MagicMock()

        mock_boto_client.side_effect = client_dispatcher

        results = cph.check_pipeline_health(ssm_wait_secs=0)
        self.assertTrue(results["sts"])
        self.assertTrue(results["s3"])
        self.assertTrue(results["lambda"])
        self.assertTrue(results["athena"])
        self.assertTrue(results["ec2"])
        self.assertTrue(results["ssm"])

    @patch("scripts.check_pipeline_health.boto3.client")
    def test_check_pipeline_health_sts_failure(self, mock_boto_client):
        """Valida que falha em credenciais STS aborta imediatamente o diagnostico."""
        import scripts.check_pipeline_health as cph

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = RuntimeError("Invalid credentials")
        mock_boto_client.return_value = mock_sts

        results = cph.check_pipeline_health(ssm_wait_secs=0)
        self.assertFalse(results["sts"])
        self.assertNotIn("s3", results)

    @patch("scripts.check_pipeline_health.time.sleep", return_value=None)
    @patch("scripts.check_pipeline_health.boto3.client")
    def test_check_pipeline_health_partial_failures(self, mock_boto_client, mock_sleep):
        """Valida tratamento gracioso de falhas nas camadas S3, Lambda, Athena e SSM desanexado."""
        import scripts.check_pipeline_health as cph

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "070443470233", "Arn": "arn:aws:iam::070443470233:user/admin"
        }

        mock_s3 = MagicMock()
        mock_s3.head_bucket.side_effect = RuntimeError("S3 Access Denied")

        mock_lambda = MagicMock()
        mock_lambda.get_function.side_effect = RuntimeError("ResourceNotFoundException")

        mock_athena = MagicMock()
        mock_athena.get_work_group.side_effect = RuntimeError("WorkGroup not found")

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"State": {"Name": "stopped"}}]}]
        }

        mock_ssm = MagicMock()
        mock_ssm.describe_instance_information.return_value = {"InstanceInformationList": []}

        def client_dispatcher(service_name, **kwargs):
            if service_name == "sts":
                return mock_sts
            elif service_name == "s3":
                return mock_s3
            elif service_name == "lambda":
                return mock_lambda
            elif service_name == "athena":
                return mock_athena
            elif service_name == "ec2":
                return mock_ec2
            elif service_name == "ssm":
                return mock_ssm
            return MagicMock()

        mock_boto_client.side_effect = client_dispatcher

        results = cph.check_pipeline_health(ssm_wait_secs=0)
        self.assertTrue(results["sts"])
        self.assertFalse(results["s3"])
        self.assertFalse(results["lambda"])
        self.assertFalse(results["athena"])
        self.assertTrue(results["ec2"])
        self.assertFalse(results["ssm"])

    @patch("scripts.check_pipeline_health.boto3.client")
    def test_check_pipeline_health_ec2_exception(self, mock_boto_client):
        """Valida tratamento de excecao geral na camada EC2/SSM."""
        import scripts.check_pipeline_health as cph

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "070443470233", "Arn": "arn:aws:iam::070443470233:user/admin"
        }

        mock_s3 = MagicMock()
        mock_lambda = MagicMock()
        mock_athena = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = RuntimeError("EC2 network error")

        def client_dispatcher(service_name, **kwargs):
            if service_name == "sts":
                return mock_sts
            elif service_name == "s3":
                return mock_s3
            elif service_name == "lambda":
                return mock_lambda
            elif service_name == "athena":
                return mock_athena
            elif service_name == "ec2":
                return mock_ec2
            return MagicMock()

        mock_boto_client.side_effect = client_dispatcher

        results = cph.check_pipeline_health(ssm_wait_secs=0)
        self.assertTrue(results["sts"])
        self.assertFalse(results["ec2"])

    def test_parse_args(self):
        """Valida parsing de argumentos CLI com valores padrao e customizados."""
        import scripts.check_pipeline_health as cph

        args_default = cph.parse_args([])
        self.assertEqual(args_default.region, cph.DEFAULT_REGION)
        self.assertEqual(args_default.instance_id, cph.DEFAULT_INSTANCE_ID)
        self.assertEqual(args_default.bucket, cph.DEFAULT_BUCKET_NAME)

        args_custom = cph.parse_args([
            "--region", "sa-east-1",
            "--instance-id", "i-custom123",
            "--bucket", "custom-bucket",
            "--lambda-name", "custom-lambda",
            "--workgroup", "custom-wg",
            "--database", "custom-db",
            "--ssm-wait-secs", "1",
            "--ssm-max-attempts", "2",
        ])
        self.assertEqual(args_custom.region, "sa-east-1")
        self.assertEqual(args_custom.instance_id, "i-custom123")
        self.assertEqual(args_custom.bucket, "custom-bucket")
        self.assertEqual(args_custom.lambda_name, "custom-lambda")
        self.assertEqual(args_custom.workgroup, "custom-wg")
        self.assertEqual(args_custom.database, "custom-db")
        self.assertEqual(args_custom.ssm_wait_secs, 1)
        self.assertEqual(args_custom.ssm_max_attempts, 2)

    @patch("scripts.check_pipeline_health.check_pipeline_health")
    def test_main_exit_codes(self, mock_check):
        """Valida que main() retorna 0 para sucesso integral e 1 para falhas."""
        import scripts.check_pipeline_health as cph

        mock_check.return_value = {
            "sts": True, "s3": True, "lambda": True, "athena": True, "ec2": True, "ssm": True
        }
        self.assertEqual(cph.main([]), 0)

        mock_check.return_value = {"sts": True, "s3": False}
        self.assertEqual(cph.main([]), 1)

        mock_check.return_value = {}
        self.assertEqual(cph.main([]), 1)

    @patch("scripts.check_pipeline_health.time.sleep", return_value=None)
    @patch("scripts.check_pipeline_health.boto3.client")
    def test_check_pipeline_health_ssm_polling_states(self, mock_boto_client, mock_sleep):
        """Valida o polling resiliente do SSM lidando com InProgress->Success, Failed e Timeout."""
        import scripts.check_pipeline_health as cph

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "070443470233", "Arn": "arn:aws:iam::070443470233:user/admin"
        }
        mock_s3 = MagicMock()
        mock_lambda = MagicMock()
        mock_athena = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"State": {"Name": "running"}, "PublicIpAddress": "1.2.3.4"}]}]
        }

        # 1. Caso com InProgress transicionando para Success
        mock_ssm = MagicMock()
        mock_ssm.describe_instance_information.return_value = {"InstanceInformationList": [{"PingStatus": "Online"}]}
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
        mock_ssm.get_command_invocation.side_effect = [
            {"Status": "InProgress"},
            {"Status": "Success", "StandardOutputContent": "Running=true"}
        ]

        def client_dispatcher(service_name, **kwargs):
            if service_name == "sts":
                return mock_sts
            if service_name == "s3":
                return mock_s3
            if service_name == "lambda":
                return mock_lambda
            if service_name == "athena":
                return mock_athena
            if service_name == "ec2":
                return mock_ec2
            if service_name == "ssm":
                return mock_ssm
            return MagicMock()

        mock_boto_client.side_effect = client_dispatcher
        res = cph.check_pipeline_health(ssm_wait_secs=0, ssm_max_attempts=3)
        self.assertTrue(res["ssm"])

        # 2. Caso com Failed retornado pelo SSM
        mock_ssm.get_command_invocation.side_effect = None
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Failed", "StandardErrorContent": "Command failed"
        }
        res_fail = cph.check_pipeline_health(ssm_wait_secs=0, ssm_max_attempts=1)
        self.assertFalse(res_fail["ssm"])

        # 3. Caso onde get_command_invocation lanca excecao persistente
        mock_ssm.get_command_invocation.side_effect = RuntimeError("InvocationDoesNotExist")
        res_err = cph.check_pipeline_health(ssm_wait_secs=0, ssm_max_attempts=1)
        self.assertFalse(res_err["ec2"])


if __name__ == "__main__":
    unittest.main()


