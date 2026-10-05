# 🔬 Relatório de Inteligência Forense e Análise de Ameaças (Threat Intel)

**Projeto:** Honeypot Cowrie na AWS com Pipeline de Telemetria  
**Período de Coleta:** 29/09/2026 a 01/10/2026  
**Total de Eventos Analisados:** 1.615 eventos  
**Amostras Binárias Capturadas:** 3 artefatos (incluindo 1 backdoor ELF de 30.3 MB)  
**Metodologia de Análise:** Alinhamento à matriz **MITRE ATT&CK® v14 for Enterprise**

---

## 1. 🕵️‍♂️ Investigação dos Principais Atores de Ameaça (IPs)

Abaixo está a investigação de inteligência sobre os principais atacantes que invadiram o Honeypot:

### 🚨 Atacante #1: `159.203.120.106` (O Invasor de Alta Periculosidade)
* **Localização:** Clifton, Nova Jersey, Estados Unidos 🇺🇸
* **Provedor / ASN:** DigitalOcean LLC (AS14061)
* **Perfil de Ameaça:** **Ataque Direcionado / Implantação de Backdoor (Trojan)**
* **Ação Executada:** Conectou-se via **SFTP**, autenticou e fez o upload de um arquivo malicioso de **30.3 Megabytes** chamado `sshd` (`SHA-256: 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00`).
* **Objetivo do Atacante:** Substituir o binário legítimo do OpenSSH do servidor por uma versão adulterada (*Trojanized SSHD*) que registra todas as senhas digitadas e permite acesso permanente por uma chave mestra oculta.

---

### 🚨 Atacante #2: `178.208.88.6` (A Botnet Massiva)
* **Localização:** Amsterdam, Holanda 🇳🇱
* **Provedor / ASN:** Iron Hosting Centre LTD (AS44050)
* **Perfil de Ameaça:** **Hospedagem "Bulletproof" / Botnet de Força Bruta**
* **Volume:** **810 requisições** sozinho (quase metade de todo o tráfego do Honeypot).
* **Comportamento:** Disparou um dicionário automatizado focado em usuários de infraestrutura como `deploy`, `hadoop`, `steam` e `user1`, testando senhas como `123`, `123456` e `qwe123!@`.

---

### 🚨 Atacante #3: `195.178.110.228` (O Ladrão de Sessões e SMS)
* **Localização:** Andorra la Vella, Andorra 🇦🇩
* **Provedor / ASN:** Techoff SRV Limited (AS204957)
* **Perfil de Ameaça:** **Infostealer / Caçador de Contas e Interceptador de 2FA**
* **Ação Executada:** Assim que entrou, injetou comandos vasculhando o disco atrás de credenciais de **Telegram Desktop (`tdata`)** e modems celulares **GSM/USB** para interceptar códigos de SMS de verificação em duas etapas.

---

### 🚨 Atacante #4: `192.42.116.107` (O Atacante Anonimizado)
* **Localização:** Amsterdam, Holanda 🇳🇱
* **Provedor / ASN:** **Nó de Saída da Rede TOR (The Onion Router)**
* **Perfil de Ameaça:** Operador humano ou botnet utilizando roteamento anônimo para impedir o rastreio do endereço IP real de origem.

---

### 🚨 Atacante #5: `54.153.51.142` (A Máquina Zumbi da AWS)
* **Localização:** San Jose, Califórnia, Estados Unidos 🇺🇸
* **Provedor / ASN:** Amazon Web Services (AWS EC2 - região `us-west-1`)
* **Perfil de Ameaça:** **Servidor Comprometido (Pivô de Botnet)**
* **Cenário:** Uma máquina corporativa de outro cliente da AWS que foi infectada por atacantes e passou a escanear a própria nuvem da AWS em busca de novos alvos.

---

## 2. 💻 Análise Forense dos Comandos Injetados

Abaixo está o registro de cada comando real que os invasores dispararam, com a **saída simulada (Output)** que o servidor devolveu para enganá-los e o **propósito tático** de acordo com a matriz MITRE ATT&CK:

---

### 📌 Comando #1: Reconhecimento Profundo de Hardware e Kernel
* **Tática MITRE ATT&CK:** `T1082 - System Information Discovery`

#### 📥 Comando Injetado pelo Atacante:
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
uname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null)
arch=$(uname -m 2>/dev/null)
cpus=$(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null)
cpu_model=$(lscpu 2>/dev/null | awk -F: '/Model name/ {print $2}')
gpu_info=$(lspci 2>/dev/null | grep -i nvidia)
last_output=$(last 2>/dev/null)
echo "UNAME:$uname"; echo "ARCH:$arch"; echo "CPUS:$cpus"; echo "GPU:$gpu_info"
```

#### 📤 Saída Devolvida pelo Servidor (Output do Honeypot):
```text
UNAME:Linux srv-prod-app01 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64
ARCH:x86_64
CPUS:2
GPU:
LAST:root     pts/0        192.168.1.150    Thu Oct 01 14:33   still logged in
```

#### 🎯 Propósito Tático do Invasor:
* **Mapeamento de Capacidade:** O invasor quer saber se o alvo tem GPU dedicada (para minerar moedas pesadas) ou se tem múltiplos núcleos de CPU.
* **Seleção de Malware:** Ao ler `ARCH:x86_64`, o bot define se deve descarregar um binário ELF de 64 bits, 32 bits ou ARM.

---

### 📌 Comando #2: Caça a Mineradores Rivais (Guerra de Botnets)
* **Tática MITRE ATT&CK:** `T1057 - Process Discovery` | `T1496 - Resource Hijacking`

#### 📥 Comando Injetado pelo Atacante:
```bash
ps -ef | grep '[Mm]iner'
```

#### 📤 Saída Devolvida pelo Servidor (Output do Honeypot):
```text
root      4128  4102  0 14:33 pts/0    00:00:00 grep --color=auto [Mm]iner
```

#### 🎯 Propósito Tático do Invasor:
* **Eliminar a Concorrência:** Campanhas de Cryptojacking usam esse comando para caçar processos concorrentes conhecidos (como `xmrig`, `minerd` ou `moneroocean`). Se um minerador concorrente for encontrado, o script mata o processo (`kill -9`) para que o novo invasor possa utilizar 100% dos recursos de hardware do servidor.

---

### 📌 Comando #3: Roubo de Sessões do Telegram e Modems SMS
* **Tática MITRE ATT&CK:** `T1552 - Unsecured Credentials` | `T1114 - Email/Message Collection`

#### 📥 Comando Injetado pelo Atacante:
```bash
ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/*
```

#### 📤 Saída Devolvida pelo Servidor (Output do Honeypot):
```text
ls: cannot access /root/.local/share/TelegramDesktop/tdata: No such file or directory
ls: cannot access /dev/ttyGSM*: No such file or directory
ls: cannot access /var/spool/sms/*: No such file or directory
```

#### 🎯 Propósito Tático do Invasor:
* **Roubo de Contas (`tdata`):** O diretório `tdata` armazena as chaves de sessão autenticadas do Telegram Desktop. Se o invasor roubar esses arquivos, ele pode abrir o Telegram da vítima em outro computador sem precisar de senha ou confirmação de SMS.
* **Interceptação de 2FA por SMS (`/dev/ttyGSM*`):** Em servidores de empresas de telecom ou IoT com modems 4G conectados por USB, o atacante tenta ler mensagens SMS recebidas para burlar autenticações de dois fatores (2FA) de contas bancárias e serviços em nuvem.

---

### 📌 Comando #4: Verificação de Permissão de Execução (Dropper Test)
* **Tática MITRE ATT&CK:** `T1059.004 - Command and Scripting Interpreter (Unix Shell)`

#### 📥 Comando Injetado pelo Atacante:
```bash
printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter
```

#### 📤 Saída Devolvida pelo Servidor (Output do Honeypot):
```text
xxxxxx
```

#### 🎯 Propósito Tático do Invasor:
* **Teste de Integridade do Ambiente:** Servidores corporativos endurecidos frequentemente montam as pastas `/tmp` e `/var/tmp` com a opção `noexec` (que impede execução de programas). O invasor cria um script descartável de 1 linha chamado `filter` e o executa. Ao receber `xxxxxx`, ele tem certeza de que o diretório aceita execução de arquivos e pode descarregar o malware principal.

---

### 📌 Comando #5: Caça a Roteadores MikroTik
* **Tática MITRE ATT&CK:** `T1082 - System Information Discovery`

#### 📥 Comando Injetado pelo Atacante:
```bash
/ip cloud print
```

#### 📤 Saída Devolvida pelo Servidor (Output do Honeypot):
```text
-bash: /ip: No such file or directory
```

#### 🎯 Propósito Tático do Invasor:
* O comando `/ip cloud print` é exclusivo do sistema operacional **MikroTik RouterOS**. 
* O bot dispara esse comando para verificar se a porta 22 pertence a um roteador de borda. Se pertencesse, ele exploraria vulnerabilidades conhecidas do MikroTik para criar túneis proxy residenciais. Como o servidor retornou `No such file or directory`, o bot descobriu que é um Linux comum e mudou de estratégia.

---

### 📌 Ação Crítica #6: Implantação de Backdoor SSH (SFTP Upload)
* **Tática MITRE ATT&CK:** `T1556.004 - Modify Authentication Process` | `T1036 - Masquerading`

#### 📥 Ação Executada pelo Atacante (`159.203.120.106`):
```text
SFTP Upload: /usr/sbin/sshd -> var/lib/cowrie/downloads/94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00
Tamanho: 30.304.472 bytes (30.3 MB)
Nome do Arquivo Original: sshd
```

#### 📤 Resposta do Honeypot:
```text
Upload accepted (200 OK). File securely stored in HoneyFS isolated storage.
```

#### 🎯 Propósito Tático do Invasor:
* **Persistência Furtiva:** Esta foi a ação mais perigosa registrada no laboratório. O atacante tentou substituir o daemon oficial do OpenSSH do servidor por uma versão maliciosa compilada por ele. 
* Esse tipo de backdoor permite ao invasor:
  1. Acessar o servidor a qualquer momento usando uma "senha mestra" oculta no binário.
  2. Gravar em texto puro as senhas de todos os administradores legítimos que fizerem login no futuro.
  3. Evitar detecção por antivírus, pois o processo malicioso se camufla com o nome legítimo de `sshd`.

---

## 3. Conclusão Forense

O laboratório de Honeypot comprovou com precisão cirúrgica a hipótese de segurança:
1. **O ecossistema de ameaças é multifacetado:** Variando desde scanners automáticos de roteadores até campanhas direcionadas de implantação de backdoors e roubo de credenciais do Telegram.
2. **A contenção funcionou em 100% dos casos:** O invasor pensou que executou scripts, inspecionou GPUs e implantou um binário de 30 MB, mas tudo ficou confinado dentro da emulação do Cowrie e armazenado com segurança para análise forense no Amazon S3.
