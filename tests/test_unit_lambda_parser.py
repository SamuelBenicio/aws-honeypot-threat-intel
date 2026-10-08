"""
Testes Unitários: Parser da Lambda e Enriquecimento GeoIP
"""

import json
from decimal import Decimal
import handler

def test_parse_cowrie_records_aggregation(sample_cowrie_raw_lines):
    """Garante que múltiplos eventos do mesmo IP são agregados em uma única entrada analítica"""
    records = handler.parse_cowrie_records(sample_cowrie_raw_lines)

    assert len(records) == 1
    atk = records[0]

    assert atk["ip"] == "198.51.100.1"
    assert atk["login_attempts"] == 2
    assert atk["successful_logins"] == 1
    assert "root" in atk["usernames"]
    assert "admin" in atk["usernames"]
    assert "123" in atk["passwords"]
    assert "admin" in atk["passwords"]
    assert "uname -a" in atk["commands"]
    assert "cat /etc/passwd" in atk["commands"]
    assert atk["downloads_count"] == 1
    assert atk["downloads"][0]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_parse_empty_and_corrupted_lines():
    """Garante resiliência a linhas vazias ou JSON inválido no arquivo de log"""
    lines = [
        "",
        "   ",
        "NOT A JSON",
        '{"invalid_structure": 123}',
        '{"eventid": "test", "src_ip": ""}'
    ]
    records = handler.parse_cowrie_records(lines)
    assert records == []

def test_geoip_local_ip_fallback():
    """Valida tratamento seguro de IPs de rede privada/interna sem consulta externa"""
    local_ips = ["127.0.0.1", "10.0.0.15", "192.168.1.1", "172.16.0.5"]
    for ip in local_ips:
        geo = handler.get_geoip_info(ip)
        assert geo["country_code"] == "LOCAL"
        assert geo["city"] == "Localhost"
        assert isinstance(geo["latitude"], Decimal)
        assert isinstance(geo["longitude"], Decimal)

def test_athena_jsonl_compatibility(sample_cowrie_raw_lines):
    """Valida se o formato serializado em JSON é 100% compatível com o Glue/Athena"""
    records = handler.parse_cowrie_records(sample_cowrie_raw_lines)
    atk = records[0]
    geo = handler.get_geoip_info(atk["ip"])

    item = {
        "ip_address": atk["ip"],
        "timestamp": atk["timestamp"],
        "country_code": geo["country_code"],
        "latitude": float(geo["latitude"]),
        "longitude": float(geo["longitude"]),
        "login_attempts": atk["login_attempts"],
        "passwords": atk["passwords"],
        "commands": atk["commands"]
    }

    serialized = json.dumps(item, ensure_ascii=False)
    deserialized = json.loads(serialized)

    assert deserialized["ip_address"] == "198.51.100.1"
    assert isinstance(deserialized["latitude"], float)
    assert isinstance(deserialized["passwords"], list)
    assert isinstance(deserialized["commands"], list)
