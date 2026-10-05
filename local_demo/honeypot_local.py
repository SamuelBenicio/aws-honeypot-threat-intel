import socket
import sys
import threading
import json
import time
from datetime import datetime, timezone
import paramiko

# Garante compatibilidade de saída no terminal Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Arquivo onde os logs de telemetria serão gravados (igual ao Cowrie na nuvem)
LOG_FILE = "cowrie_simulado.json"

def log_event(event_type, client_ip, data):
    """Grava o evento no formato JSON que o Cowrie gera e que o Lambda processa"""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eventid": event_type,
        "src_ip": client_ip,
        **data
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print(f"\n[ALERTA DE INTRUSAO] Tentativa de login capturada!")
        print(f"   |-- IP de Origem : {self.client_ip}")
        print(f"   |-- Usuario      : {username}")
        print(f"   \\-- Senha testada: {password}")
        
        # Grava no log simulado do Cowrie
        log_event("cowrie.login.success", self.client_ip, {
            "username": username,
            "password": password,
            "message": "Login aceito pelo Honeypot"
        })
        
        # Retorna SUCESSO propositalmente para iludir o invasor!
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_fake_shell(channel, client_ip):
    """Simula um terminal Linux falso interativo para o invasor brincar sem perigo"""
    banner = (
        "\r\nWelcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-40-generic x86_64)\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/pro\r\n\r\n"
        "Last login: Sun Sep 27 14:22:01 2026 from 192.168.1.10\r\n"
    )
    channel.send(banner.encode('utf-8'))

    prompt = "root@ubuntu-srv-lab:~# "
    channel.send(prompt.encode('utf-8'))

    cmd_buffer = ""
    while True:
        try:
            char = channel.recv(1).decode('utf-8', errors='ignore')
            if not char:
                break

            # Tecla ENTER pressionada
            if char in ('\r', '\n'):
                channel.send(b"\r\n")
                command = cmd_buffer.strip()
                cmd_buffer = ""

                if command:
                    print(f"\n[COMANDO DO INVASOR]: '{command}' (IP: {client_ip})")
                    log_event("cowrie.command.input", client_ip, {"input": command})

                    # Respostas falsas inteligentes
                    if command == "exit":
                        channel.send(b"logout\r\n")
                        break
                    elif command == "whoami":
                        channel.send(b"root\r\n")
                    elif command == "id":
                        channel.send(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                    elif command.startswith("ls"):
                        channel.send(b"backup.tar.gz  passwords.txt  app.py  secrets.env\r\n")
                    elif command == "pwd":
                        channel.send(b"/root\r\n")
                    elif command.startswith("cat passwords.txt") or command.startswith("cat secrets.env"):
                        channel.send(b"DB_USER=admin\r\nDB_PASS=Sup3rS3cr3t!2026\r\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\r\n")
                    elif command.startswith("uname"):
                        channel.send(b"Linux ubuntu-srv-lab 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC x86_64\r\n")
                    else:
                        channel.send(f"bash: {command.split()[0]}: command not found\r\n".encode('utf-8'))

                channel.send(prompt.encode('utf-8'))
            elif char == '\x03': # Ctrl+C
                channel.send(b"^C\r\n" + prompt.encode('utf-8'))
                cmd_buffer = ""
            elif char == '\x7f' or char == '\x08': # Backspace
                if len(cmd_buffer) > 0:
                    cmd_buffer = cmd_buffer[:-1]
                    channel.send(b"\b \b")
            else:
                cmd_buffer += char
                channel.send(char.encode('utf-8')) # Echo local
        except Exception:
            break

    channel.close()
    print(f"[-] Sessao encerrada para {client_ip}")

def run_honeypot_server(port=2222):
    # Gera chave de servidor SSH temporária
    host_key = paramiko.RSAKey.generate(2048)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind(('0.0.0.0', port))
    except PermissionError:
        print(f"Erro: Porta {port} requer privilegios de Administrador.")
        return
    except Exception as e:
        print(f"Erro ao abrir porta {port}: {e}")
        return

    server_sock.listen(10)
    print("=" * 65)
    print(f"[HONEYPOT SSH LOCAL INICIADO NA PORTA {port} (TCP)]")
    print(f"Arquivo de Telemetria: {LOG_FILE}")
    print("=" * 65)
    print(f"-> Abra OUTRO terminal no seu Windows e digite o comando:")
    print(f"   ssh root@localhost -p {port}")
    print(f"-> Digite qualquer senha (ex: 123456, admin, teste)...")
    print("=" * 65)
    print("[*] Aguardando invasor bater na porta...\n")

    while True:
        try:
            client, addr = server_sock.accept()
            client_ip = addr[0]
            
            transport = paramiko.Transport(client)
            transport.add_server_key(host_key)
            
            server = FakeSSHServer(client_ip)
            transport.start_server(server=server)

            chan = transport.accept(20)
            if chan is not None:
                threading.Thread(target=handle_fake_shell, args=(chan, client_ip), daemon=True).start()
        except KeyboardInterrupt:
            print("\nEncerrando Honeypot local...")
            break
        except Exception as e:
            # print(f"Erro na conexão: {e}")
            pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
    run_honeypot_server(port)
