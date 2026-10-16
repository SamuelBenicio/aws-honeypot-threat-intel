"""
Testes de Integridade do Sistema e Nao-Regressao
Garante que todas as frentes da infraestrutura e dos pipelines anteriores
permanecem intactas e operacionais apos a integracao do modulo forense de malware:
- Frente 1: Ingestao, agregacao e alertas de telemetria Cowrie
- Frente 2: Enriquecimento isolado de GeoIP e AbuseIPDB
- Frente 3: Integridade de esquema no AWS Glue / Athena (enriched_attacks e enriched_malware)
- Frente 4: Isolamento de prefixos S3 e prevencao de recursao no Lambda
- Frente 5: Salvaguardas FinOps (limites de escaneamento Athena e lifecycles S3)
- Frente 6: Integridade do Dashboard Grafana SOC
"""

import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

import handler

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestHoneypotIngestionIntegrity:
    """Valida que a ingestao e agregacao de eventos do Cowrie continuam funcionando perfeitamente."""

    def test_parse_cowrie_records_aggregation_fidelity(self):
        records = [
            '{"eventid":"cowrie.session.connect","src_ip":"198.51.100.10","session":"s1","timestamp":"2026-10-12T10:00:00Z"}',
            '{"eventid":"cowrie.client.version","src_ip":"198.51.100.10","session":"s1","timestamp":"2026-10-12T10:00:01Z"}',
            '{"eventid":"cowrie.login.failed","src_ip":"198.51.100.10","username":"root","password":"123","session":"s1","timestamp":"2026-10-12T10:00:02Z"}',
            '{"eventid":"cowrie.login.success","src_ip":"198.51.100.10","username":"admin","password":"admin","session":"s1","timestamp":"2026-10-12T10:00:03Z"}',
            '{"eventid":"cowrie.command.input","src_ip":"198.51.100.10","input":"uname -a","session":"s1","timestamp":"2026-10-12T10:00:04Z"}',
            '{"eventid":"cowrie.command.input","src_ip":"198.51.100.10","input":"cat /etc/passwd","session":"s1","timestamp":"2026-10-12T10:00:05Z"}',
            '{"eventid":"cowrie.session.file_download","src_ip":"198.51.100.10","shasum":"abc123sha","destfile":"/tmp/a.sh","session":"s1","timestamp":"2026-10-12T10:00:06Z"}',
            '{"eventid":"cowrie.session.closed","src_ip":"198.51.100.10","session":"s1","timestamp":"2026-10-12T10:00:07Z"}'
        ]

        result = handler.parse_cowrie_records(records)
        assert len(result) == 1
        item = result[0]

        assert item["ip"] == "198.51.100.10"
        assert item["login_attempts"] == 2
        assert item["successful_logins"] == 1
        assert "root" in item["usernames"]
        assert "admin" in item["usernames"]
        assert "123" in item["passwords"]
        assert "admin" in item["passwords"]
        assert item["commands"] == ["uname -a", "cat /etc/passwd"]
        assert item["downloads_count"] == 1
        assert item["downloads"][0]["sha256"] == "abc123sha"
        assert item["ttl_timestamp"] > 0

    def test_send_discord_notification_no_emojis(self, monkeypatch):
        monkeypatch.setattr(handler, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/mock")

        event = {
            "ip_address": "198.51.100.10",
            "country_name": "Brazil",
            "abuse_score": 95,
            "successful_logins": 1,
            "commands": ["id", "uname -a"]
        }

        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_url:
            handler.send_discord_notification(event)
            assert mock_url.called
            req = mock_url.call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            embed = body["embeds"][0]
            assert "[ALERTA] Honeypot Comprometido" in embed["title"]
            # Garante ausencia de emojis
            for char in embed["title"]:
                assert ord(char) < 0x1F000


class TestEnrichmentIsolation:
    """Valida que o enriquecimento de telemetria e o enriquecimento de malwares sao estritamente isolados."""

    def test_geoip_resolution_and_cache(self):
        handler.GEOIP_CACHE.clear()

        # IP local
        local_res = handler.get_geoip_info("192.168.1.100")
        assert local_res["country_code"] == "LOCAL"
        assert local_res["latitude"] == Decimal("0.0")

        # IP externo simulado
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "success": True,
            "country_code": "US",
            "country": "United States",
            "city": "Ashburn",
            "latitude": 39.0438,
            "longitude": -77.4874,
            "connection": {"isp": "Amazon Technologies Inc."}
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = handler.get_geoip_info("54.210.1.1")
            assert res["country_code"] == "US"
            assert res["city"] == "Ashburn"

        # Segunda chamada deve atingir cache sem requisicao de rede
        with patch("urllib.request.urlopen") as mock_url:
            cached_res = handler.get_geoip_info("54.210.1.1")
            mock_url.assert_not_called()
            assert cached_res["country_code"] == "US"

    def test_abuseipdb_fallback_and_caching(self, monkeypatch):
        handler.ABUSE_CACHE.clear()
        monkeypatch.setattr(handler, "ABUSEIPDB_API_KEY", "")

        # Sem chave de API -> fallback imediato
        fb = handler.get_abuseipdb_score("198.51.100.50")
        assert fb["abuse_checked"] is False
        assert fb["abuse_score"] == 0

        # Com chave de API simulada
        monkeypatch.setattr(handler, "ABUSEIPDB_API_KEY", "dummy_key")
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "abuseConfidenceScore": 87,
                "totalReports": 34,
                "isWhitelisted": False
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = handler.get_abuseipdb_score("198.51.100.50")
            assert res["abuse_checked"] is True
            assert res["abuse_score"] == 87
            assert res["total_reports"] == 34


class TestAthenaGlueSchemaIntegrity:
    """Valida conformidade das tabelas Glue Catalog enriched_attacks e enriched_malware."""

    def test_athena_tables_definition_in_terraform(self):
        athena_tf = (ROOT_DIR / "terraform" / "athena.tf").read_text(encoding="utf-8")

        # Verifica tabela enriched_attacks
        assert 'resource "aws_glue_catalog_table" "enriched_attacks"' in athena_tf
        expected_attack_cols = [
            "ip_address", "timestamp", "first_seen", "country_code", "country_name",
            "city", "latitude", "longitude", "isp", "abuse_score", "total_reports",
            "sessions_count", "login_attempts", "successful_logins", "usernames",
            "passwords", "commands", "downloads_count"
        ]
        for col in expected_attack_cols:
            assert f'name = "{col}"' in athena_tf

        # Verifica tabela enriched_malware
        assert 'resource "aws_glue_catalog_table" "enriched_malware"' in athena_tf
        expected_malware_cols = [
            "sha256", "md5", "timestamp", "file_name", "file_size_bytes",
            "magic_type", "malware_family", "vt_positives", "vt_total",
            "vt_permalink", "extracted_ips", "extracted_urls", "yara_tags"
        ]
        for col in expected_malware_cols:
            assert f'name = "{col}"' in athena_tf

        # Verifica utilizacao de JsonSerDe com ignore.malformed.json
        assert '"org.openx.data.jsonserde.JsonSerDe"' in athena_tf
        assert '"ignore.malformed.json" = "TRUE"' in athena_tf


class TestS3PartitioningAndPrefixIsolation:
    """Garante que nao ocorrem colisoes ou loops de recursao entre prefixos S3."""

    def test_s3_prefix_independence(self):
        lambda_tf = (ROOT_DIR / "terraform" / "lambda.tf").read_text(encoding="utf-8")

        # Notificacao do S3 dispara exclusivamente para cowrie-logs/ e malware-samples/
        assert 'filter_prefix       = "cowrie-logs/"' in lambda_tf
        assert 'filter_prefix       = "malware-samples/"' in lambda_tf

        # Garante que os destinos gravados nunca sao os mesmos dos gatilhos (prevencao de loop infinito)
        assert 'filter_prefix       = "enriched-telemetry/"' not in lambda_tf
        assert 'filter_prefix       = "enriched-malware/"' not in lambda_tf

    def test_lambda_routing_strict_separation(self, monkeypatch):
        mock_process_malware = MagicMock()
        mock_parse = MagicMock()
        monkeypatch.setattr(handler, "process_malware_sample", mock_process_malware)

        # 1. Objeto de logs brutos
        evt_logs = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-b"},
                        "object": {"key": "cowrie-logs/year=2026/month=10/day=12/cowrie_test.json"}
                    }
                }
            ]
        }
        mock_s3 = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = b'{"eventid":"cowrie.session.connect","src_ip":"1.1.1.2"}\n'
        mock_s3.get_object.return_value = {"Body": mock_body}
        monkeypatch.setattr(handler, "s3_client", mock_s3)

        handler.lambda_handler(evt_logs, None)
        mock_process_malware.assert_not_called()

        # 2. Objeto de malware
        evt_malware = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-b"},
                        "object": {"key": "malware-samples/abc123hash"}
                    }
                }
            ]
        }
        handler.lambda_handler(evt_malware, None)
        mock_process_malware.assert_called_once_with("test-b", "malware-samples/abc123hash")

        # 3. Objeto de resultado enriquecido (deve ser totalmente ignorado)
        evt_enriched = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-b"},
                        "object": {"key": "enriched-malware/enriched_abc.json"}
                    }
                }
            ]
        }
        res = handler.lambda_handler(evt_enriched, None)
        assert res["total_processed"] == 0


class TestFinOpsSafeguardsIntegrity:
    """Valida politicas de retencao e limites de custo zero."""

    def test_s3_lifecycle_rules_exist_for_all_prefixes(self):
        s3_tf = (ROOT_DIR / "terraform" / "s3.tf").read_text(encoding="utf-8")

        expected_rules = [
            "expire-raw-logs",
            "expire-enriched-telemetry",
            "expire-athena-query-results",
            "expire-malware-samples",
            "expire-enriched-malware"
        ]
        for rule_id in expected_rules:
            assert f'id     = "{rule_id}"' in s3_tf

    def test_athena_cutoff_limit_enforced(self):
        athena_tf = (ROOT_DIR / "terraform" / "athena.tf").read_text(encoding="utf-8")
        assert "bytes_scanned_cutoff_per_query = 104857600" in athena_tf


class TestGrafanaDashboardIntegrity:
    """Valida integridade do painel Grafana SOC sem erros de sintaxe ou emojis."""

    def test_dashboard_json_structure_and_queries(self):
        dashboard_path = ROOT_DIR / "grafana" / "honeypot_soc_dashboard.json"
        assert dashboard_path.exists()

        content = dashboard_path.read_text(encoding="utf-8")
        data = json.loads(content)

        assert data["title"] == "Threat Intelligence - Cowrie Honeypot SOC"
        assert len(data["panels"]) == 18

        # Valida que todos os paineis possuem titulo e tipo
        for panel in data["panels"]:
            assert "title" in panel
            assert "type" in panel
            assert "gridPos" in panel

        # Garante ausencia de emojis no arquivo do dashboard
        for char in content:
            assert ord(char) < 0x1F000
            assert ord(char) not in [0x2623, 0x2728, 0x1F6A8]

    def test_lambda_timeout_guard_and_parallel_prewarm(self, monkeypatch):
        """
        Valida que:
        1. _prewarm_ip_caches enriquece multiplos IPs em paralelo quando ha tempo suficiente.
        2. Quando o tempo restante do container Lambda cai abaixo do limite de seguranca (10s),
           o handler ignora chamadas de rede lentas e grava imediatamente no S3 usando fallback local.
        """
        handler.GEOIP_CACHE.clear()
        handler.ABUSE_CACHE.clear()
        monkeypatch.setattr(handler, "ABUSEIPDB_API_KEY", "dummy_key")

        # 1. Contexto com bastante tempo (60s) -> deve pre-aquecer multiplos IPs em paralelo
        ctx_ok = MagicMock()
        ctx_ok.get_remaining_time_in_millis.return_value = 60000
        assert handler._has_sufficient_time(ctx_ok) is True

        with patch.object(handler, "get_geoip_info") as m_geo, patch.object(handler, "get_abuseipdb_score") as m_abuse:
            handler._prewarm_ip_caches(["198.51.100.1", "198.51.100.2"], context=ctx_ok)
            assert m_geo.call_count == 2
            assert m_abuse.call_count == 2

        # 2. Contexto prestes a sofrer timeout (3s restantes) -> deve usar fallback sem rede e salvar no S3
        ctx_low = MagicMock()
        ctx_low.get_remaining_time_in_millis.return_value = 3000
        assert handler._has_sufficient_time(ctx_low) is False

        # Contexto que levanta excecao ao consultar tempo -> deve retornar True de forma segura
        ctx_err = MagicMock()
        ctx_err.get_remaining_time_in_millis.side_effect = RuntimeError("No context")
        assert handler._has_sufficient_time(ctx_err) is True

        evt = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-b"},
                        "object": {"key": "cowrie-logs/year=2026/month=10/day=16/cowrie_burst.json"}
                    }
                }
            ]
        }
        mock_s3 = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = (
            b'{"eventid":"cowrie.login.failed","src_ip":"203.0.113.10","username":"root","password":"123"}\n'
            b'{"eventid":"cowrie.login.failed","src_ip":"203.0.113.11","username":"admin","password":"123"}\n'
        )
        mock_s3.get_object.return_value = {"Body": mock_body}
        monkeypatch.setattr(handler, "s3_client", mock_s3)

        with patch.object(handler, "get_geoip_info") as m_geo_low:
            res = handler.lambda_handler(evt, ctx_low)
            assert res["total_processed"] == 2
            m_geo_low.assert_not_called()
            assert mock_s3.put_object.called

    def test_process_malware_sample_read_no_args_fallback(self, monkeypatch):
        """Valida fallback caso o stream Body.read() nao aceite argumento posicional de limite de bytes."""
        class StrictNoArgStream:
            def read(self):
                return b"#!/bin/sh\necho test\n"

        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": StrictNoArgStream()}
        monkeypatch.setattr(handler, "s3_client", mock_s3)
        monkeypatch.setattr(handler, "VIRUSTOTAL_API_KEY", "")
        monkeypatch.setattr(handler, "DISCORD_WEBHOOK_URL", "")

        res = handler.process_malware_sample("test-b", "malware-samples/hash_noarg")
        assert res["sha256"] == "hash_noarg"
        assert res["magic_type"] == "Linux Shell Script"

    def test_positive_only_cache_and_eviction_limit(self, monkeypatch):
        """
        Valida que falhas transientes de rede nao envenenam os caches (GEOIP_CACHE, ABUSE_CACHE, VT_CACHE)
        e que _cache_set respeita o teto MAX_CACHE_ENTRIES.
        """
        handler.GEOIP_CACHE.clear()
        handler.ABUSE_CACHE.clear()
        handler.VT_CACHE.clear()
        monkeypatch.setattr(handler, "ABUSEIPDB_API_KEY", "dummy_key")
        monkeypatch.setattr(handler, "VIRUSTOTAL_API_KEY", "dummy_vt")

        with patch("urllib.request.urlopen", side_effect=RuntimeError("Transient network blip")):
            g_fb = handler.get_geoip_info("203.0.113.55")
            a_fb = handler.get_abuseipdb_score("203.0.113.55")
            v_fb = handler.get_virustotal_report("sha_transient")

        assert g_fb["country_code"] == "XX"
        assert a_fb["abuse_checked"] is False
        assert v_fb["vt_checked"] is False

        # Nenhum erro transiente deve ter sido persistido em cache
        assert "203.0.113.55" not in handler.GEOIP_CACHE
        assert "203.0.113.55" not in handler.ABUSE_CACHE
        assert "sha_transient" not in handler.VT_CACHE

        # Testa eviccao automatica quando o cache atinge MAX_CACHE_ENTRIES
        monkeypatch.setattr(handler, "MAX_CACHE_ENTRIES", 2)
        handler._cache_set(handler.GEOIP_CACHE, "1.1.1.1", {"country_code": "AU"})
        handler._cache_set(handler.GEOIP_CACHE, "1.1.1.2", {"country_code": "US"})
        assert len(handler.GEOIP_CACHE) == 2
        handler._cache_set(handler.GEOIP_CACHE, "1.1.1.3", {"country_code": "BR"})
        assert len(handler.GEOIP_CACHE) == 1
        assert "1.1.1.3" in handler.GEOIP_CACHE
