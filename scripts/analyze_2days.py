import glob
import json
import urllib.request
from collections import Counter, defaultdict


def load_events_from_files(files):
    """Carrega e desserializa eventos JSON a partir de uma lista de caminhos de arquivos."""
    all_events = []
    for f in files:
        with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
            for line in fp:
                line = line.strip()
                if line:
                    try:
                        all_events.append(json.loads(line))
                    except Exception:
                        pass
    return all_events


def filter_and_aggregate_metrics(all_events, operator_ip='187.15.86.243'):
    """Filtra eventos excluindo o IP do operador e calcula as métricas consolidadas."""
    filtered_events = [e for e in all_events if e.get('src_ip') != operator_ip]

    sessions = set(e.get('session') for e in filtered_events if e.get('session'))
    ips = [e.get('src_ip') for e in filtered_events if e.get('src_ip')]
    ip_counts = Counter(ips)

    logins = [e for e in filtered_events if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed')]
    success_logins = [e for e in filtered_events if e.get('eventid') == 'cowrie.login.success']
    failed_logins = [e for e in filtered_events if e.get('eventid') == 'cowrie.login.failed']

    cred_pairs = [(e.get('username', ''), e.get('password', '')) for e in logins]
    cred_counts = Counter(cred_pairs)

    users = [e.get('username', '') for e in logins if e.get('username')]
    passwords = [e.get('password', '') for e in logins if e.get('password')]

    uploads = [e for e in filtered_events if e.get('eventid') == 'cowrie.session.file_upload']
    cmds = [e for e in filtered_events if e.get('eventid') == 'cowrie.command.input']

    return {
        "filtered_events": filtered_events,
        "sessions": sessions,
        "ip_counts": ip_counts,
        "logins": logins,
        "success_logins": success_logins,
        "failed_logins": failed_logins,
        "cred_counts": cred_counts,
        "user_counts": Counter(users),
        "password_counts": Counter(passwords),
        "uploads": uploads,
        "cmds": cmds,
    }


def fetch_geoip_metadata(ip):
    """Consulta metadados de geolocalização e ISP para um IP."""
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            return {
                "country": data.get("country", "N/A"),
                "city": data.get("city", "N/A"),
                "isp": data.get("isp", "N/A"),
                "as": data.get("as", "N/A")
            }
    except Exception:
        return {"country": "N/A", "city": "N/A", "isp": "N/A", "as": "N/A"}


def main():
    files = sorted(glob.glob('logs_salvos/year=2026/month=10/day=0[678]/*.json'))
    all_events = load_events_from_files(files)
    metrics = filter_and_aggregate_metrics(all_events)

    filtered_events = metrics["filtered_events"]
    sessions = metrics["sessions"]
    ip_counts = metrics["ip_counts"]
    logins = metrics["logins"]
    success_logins = metrics["success_logins"]
    failed_logins = metrics["failed_logins"]
    cred_counts = metrics["cred_counts"]

    print("=== METRICAS GERAIS (2 DIAS) ===")
    print(f"Total de eventos maliciosos: {len(filtered_events):,}")
    print(f"Total de sessoes SSH de atacantes: {len(sessions):,}")
    print(f"Total de IPs unicos de atacantes: {len(ip_counts):,}")
    print(f"Total de tentativas de login: {len(logins):,}")
    print(f"Logins aceitos (engodo): {len(success_logins):,}")
    print(f"Logins rejeitados: {len(failed_logins):,}")

    print("\n=== TOP 10 USUARIOS TESTADOS ===")
    for u, c in metrics["user_counts"].most_common(10):
        print(f"- {u}: {c}")

    print("\n=== TOP 10 SENHAS TESTADAS ===")
    for p, c in metrics["password_counts"].most_common(10):
        print(f"- {p}: {c}")

    print("\n=== TOP 10 CREDENCIAIS (USER:PASS) ===")
    for (u, p), c in cred_counts.most_common(10):
        print(f"- {u}:{p} -> {c}x")

    print("\n=== TOP 15 IPS COM MAIS ATIVIDADE ===")
    top_ips = [ip for ip, _ in ip_counts.most_common(15)]
    geo_results = {ip: fetch_geoip_metadata(ip) for ip in top_ips}

    for ip, cnt in ip_counts.most_common(15):
        g = geo_results.get(ip, {})
        print(f"- {ip} ({cnt} eventos) | {g.get('country')}, {g.get('city')} | ISP: {g.get('isp')} | ASN: {g.get('as')}")

    print("\n=== COMPROMETIMENTOS BEM SUCEDIDOS (LOGIN SUCCESS) ===")
    for sl in success_logins:
        ts = sl.get('timestamp')
        ip = sl.get('src_ip')
        u = sl.get('username')
        p = sl.get('password')
        sid = sl.get('session')
        print(f"Data: {ts} | IP: {ip} | User: {u} | Pass: {p} | Session: {sid}")

    print("\n=== ARQUIVOS ENVIADOS (FILE UPLOAD) ===")
    for up in metrics["uploads"]:
        print(f"Data: {up.get('timestamp')} | IP: {up.get('src_ip')} | Nome: {up.get('filename')} | SHA256: {up.get('shasum')}")

    print("\n=== COMANDOS EXECUTADOS NA SHELL ===")
    for cm in metrics["cmds"]:
        print(f"Data: {cm.get('timestamp')} | IP: {cm.get('src_ip')} | Cmd: {cm.get('input')}")


if __name__ == "__main__":
    main()
