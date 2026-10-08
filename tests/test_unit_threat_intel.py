"""
Testes Unitários: Resiliência de Threat Intelligence e Alertas
"""

import handler

def test_abuseipdb_fallback_when_no_api_key(monkeypatch):
    """Garante que a ausência de chave de API não trava a Lambda e retorna fallback limpo"""
    monkeypatch.setattr(handler, "ABUSEIPDB_API_KEY", "")
    score_data = handler.get_abuseipdb_score("203.0.113.195")

    assert score_data["abuse_score"] == 0
    assert score_data["total_reports"] == 0
    assert score_data["abuse_checked"] is False

def test_discord_notification_skips_irrelevant_probes(monkeypatch):
    """Garante que probes de rede sem login aceito e sem comandos não disparam webhooks redundantes"""
    called = []
    def fake_urlopen(*args, **kwargs):
        called.append(True)

    monkeypatch.setattr(handler.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(handler, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/fake")

    # Ataque sem login bem-sucedido e sem comandos
    event_irrelevant = {
        "ip_address": "198.51.100.5",
        "successful_logins": 0,
        "commands": []
    }
    handler.send_discord_notification(event_irrelevant)
    assert len(called) == 0

    # Ataque crítico (comprometimento / login com sucesso)
    event_critical = {
        "ip_address": "198.51.100.5",
        "country_name": "Rússia",
        "abuse_score": 100,
        "successful_logins": 1,
        "commands": ["cat /etc/shadow"]
    }
    handler.send_discord_notification(event_critical)
    assert len(called) == 1
