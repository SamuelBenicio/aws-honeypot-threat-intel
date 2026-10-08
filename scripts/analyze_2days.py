import glob
import json
import urllib.request
from collections import Counter, defaultdict

files = sorted(glob.glob('logs_salvos/year=2026/month=10/day=0[678]/*.json'))

all_events = []
for f in files:
    with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
        for line in fp:
            line = line.strip()
            if line:
                try:
                    all_events.append(json.loads(line))
                except:
                    pass

operator_ip = '187.15.86.243'
filtered_events = [e for e in all_events if e.get('src_ip') != operator_ip]

sessions = set(e.get('session') for e in filtered_events if e.get('session'))
ips = [e.get('src_ip') for e in filtered_events if e.get('src_ip')]
ip_counts = Counter(ips)

logins = [e for e in filtered_events if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed')]
success_logins = [e for e in filtered_events if e.get('eventid') == 'cowrie.login.success']
failed_logins = [e for e in filtered_events if e.get('eventid') == 'cowrie.login.failed']

cred_pairs = [(e.get('username',''), e.get('password','')) for e in logins]
cred_counts = Counter(cred_pairs)

users = [e.get('username','') for e in logins if e.get('username')]
passwords = [e.get('password','') for e in logins if e.get('password')]

print("=== METRICAS GERAIS (2 DIAS) ===")
print(f"Total de eventos maliciosos: {len(filtered_events):,}")
print(f"Total de sessoes SSH de atacantes: {len(sessions):,}")
print(f"Total de IPs unicos de atacantes: {len(ip_counts):,}")
print(f"Total de tentativas de login: {len(logins):,}")
print(f"Logins aceitos (engodo): {len(success_logins):,}")
print(f"Logins rejeitados: {len(failed_logins):,}")

print("\n=== TOP 10 USUARIOS TESTADOS ===")
for u, c in Counter(users).most_common(10):
    print(f"- {u}: {c}")

print("\n=== TOP 10 SENHAS TESTADAS ===")
for p, c in Counter(passwords).most_common(10):
    print(f"- {p}: {c}")

print("\n=== TOP 10 CREDENCIAIS (USER:PASS) ===")
for (u, p), c in cred_counts.most_common(10):
    print(f"- {u}:{p} -> {c}x")

print("\n=== TOP 15 IPS COM MAIS ATIVIDADE ===")
top_ips = [ip for ip, _ in ip_counts.most_common(15)]

geo_results = {}
for ip in top_ips:
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            geo_results[ip] = {
                "country": data.get("country", "N/A"),
                "city": data.get("city", "N/A"),
                "isp": data.get("isp", "N/A"),
                "as": data.get("as", "N/A")
            }
    except Exception as ex:
        geo_results[ip] = {"country": "N/A", "city": "N/A", "isp": "N/A", "as": "N/A"}

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
uploads = [e for e in filtered_events if e.get('eventid') == 'cowrie.session.file_upload']
for up in uploads:
    print(f"Data: {up.get('timestamp')} | IP: {up.get('src_ip')} | Nome: {up.get('filename')} | SHA256: {up.get('shasum')}")

print("\n=== COMANDOS EXECUTADOS NA SHELL ===")
cmds = [e for e in filtered_events if e.get('eventid') == 'cowrie.command.input']
for cm in cmds:
    print(f"Data: {cm.get('timestamp')} | IP: {cm.get('src_ip')} | Cmd: {cm.get('input')}")
