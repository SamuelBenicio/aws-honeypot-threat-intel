# 🚨 Relatório de Threat Intelligence: Invasores Reais Capturados

**Data da Coleta:** 01/10/2026  
**Período de Monitoramento:** ~20 horas contínuas na AWS  
**Status do Honeypot:** 100% Operacional e Ativo  

---

## 📊 Resumo Executivo das Ameaças

- **Total de Eventos Registrados:** `1,615`
- **Endereços IP Únicos de Atacantes:** `36`
- **Tentativas de Autenticação Forçada (Brute-Force):** `142`
- **Comandos Maliciosos Injetados na Shell:** `78`

---

## 🌍 Top 10 IPs Atacantes e Origem Geográfica

| Endereço IP | Eventos | País / Cidade | Provedor / ASN |
| :--- | :--- | :--- | :--- |
| `178.208.88.6` | **810** | The Netherlands (Amsterdam) | Iron Hosting Centre LTD |
| `39.152.6.7` | **530** | China (Shenyang) | China Mobile Communications Group Co., Ltd |
| `195.178.110.228` | **56** | Andorra (Andorra la Vella) | Techoff SRV Limited |
| `189.223.176.45` | **33** | Mexico (Mexicali) | Telefonos del Noroeste, S.A. de C.V |
| `103.170.215.118` | **33** | India (Mumbai) | SSV Telecom Private Limited |
| `54.153.51.142` | **32** | United States (San Jose) | AWS EC2 (us-west-1) |
| `192.42.116.107` | **10** | The Netherlands (Amsterdam) | TOR Exit and More |
| `159.203.120.106` | **9** | United States (Clifton) | Digital Ocean |
| `4.148.240.235` | **7** | United States (Phoenix) | Microsoft Azure Cloud (westus3) |
| `146.190.56.107` | **6** | United States (Santa Clara) | DigitalOcean, LLC |

---

## 🔑 Principais Credenciais Testadas pelos Bots (Dicionário de Força Bruta)

| Usuário Alvo | Senha Testada | Frequência |
| :--- | :--- | :--- |
| `ubuntu` | `usuario` | 2x |
| `root` | `root` | 1x |
| `admin2` | `admin2` | 1x |
| `adminuser` | `adminuser` | 1x |
| `amir` | `123456` | 1x |
| `azureuser` | `azureuser` | 1x |
| `backup` | `backup` | 1x |
| `data` | `data` | 1x |
| `root` | `qwe123!@` | 1x |
| `elasticsearch` | `elasticsearch@1234` | 1x |
| `esroot` | `esroot` | 1x |
| `frappe` | `frappe` | 1x |
| `frappe` | `frappe@123` | 1x |
| `init` | `init` | 1x |
| `joel` | `joel` | 1x |

---

## 💻 Comandos Mais Injetados pelos Invasores na Máquina

Estes são os scripts reais que os invasores dispararam assim que o Honeypot aceitou a conexão:

### ⚙️ Executado 44x:
```bash
uname -s -v -n -r -m
```

### ⚙️ Executado 6x:
```bash
printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter
```

### ⚙️ Executado 6x:
```bash
#!/bin/bash
echo "xxxxxx"

```

### ⚙️ Executado 3x:
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
uname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null || /usr/bin/uname -s -v -n -m 2>/dev/null || busybox uname -s -v -n -m 2>/dev/null || ( [ -f /proc/version ] && head -1 /proc/version | cut -d' ' -f1 ) || ( [ -f /etc/os-release ] && grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' ) || echo "")
arch=$(uname -m 2>/dev/null || /bin/uname -m 2>/dev/null || /usr/bin/uname -m 2>/dev/null || busybox uname -m 2>/dev/null || ( [ -f /proc/cpuinfo ] && grep -q "lm" /proc/cpuinfo && echo x86_64 ) || ( [ -f /proc/cpuinfo ] && grep -q "CPU architecture: 8" /proc/cpuinfo && echo aarch64 ) || ( [ -f /proc/cpuinfo ] && grep -q "CPU architecture: 7" /proc/cpuinfo && echo armv7l ) || echo "")
uptime=$(cat /proc/uptime 2>/dev/null || busybox cat /proc/uptime 2>/dev/null)
cpus=$(nproc 2>/dev/null || /usr/bin/nproc 2>/dev/null || busybox nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null)
cpu_model=$( { lscpu 2>/dev/null | awk -F: '/Model name/ {print $2}'; grep -m1 -E "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2-; grep -m1 -E "^Hardware" /proc/cpuinfo 2>/dev/null | cut -d: -f2-; cat /proc/device-tree/model 2>/dev/null; } | sed '/^$/d; /unknown/d; s/^[[:space:]]*//; s/[[:space:]]*$//; s/ AArch64 Processor$//; s/ Processor$//; s/ CPU$//' | head -1 )
gpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia; busybox lspci 2>/dev/null | grep -i vga; busybox lspci 2>/dev/null | grep -i nvidia) 2>/dev/null )
last_output=$(last 2>/dev/null)
filter_output=$( ( export LANG=C LC_ALL=C; echo '===SHELL_BEHAVIOR==='; printf 'path_err='; ( ./xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d '\n' 2>/dev/null || busybox tr -d '\n' 2>/dev/null || cat ); printf '\n'; printf 'cmd_err='; ( xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d '\n' 2>/dev/null || busybox tr -d '\n' 2>/dev/null || cat ); printf '\n'; printf 'execute_err='; out=$(bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(/bin/bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(/usr/bin/bash -c 'printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(busybox sh -c 'printf "#!/bin/sh\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1 || sh -c 'printf "#!/bin/sh\necho \"xxxxxx\"\n" > filter && chmod +x filter && ./filter && rm -rf filter' 2>&1); esac; esac; esac; printf '%s' "$out" | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d '\n' 2>/dev/null || busybox tr -d '\n' 2>/dev/null || cat ); printf '\n'; echo '===DONE===' ) 2>&1 )
echo "UNAME:$uname"
echo "ARCH:$arch"
echo "UPTIME:$uptime"
echo "CPUS:$cpus"
echo "CPU_MODEL:$cpu_model"
echo "GPU:$gpu_info"
echo "LAST:$last_output"
echo "FILTER:$filter_output"
```

### ⚙️ Executado 2x:
```bash
/ip cloud print
```

### ⚙️ Executado 2x:
```bash
ifconfig
```

### ⚙️ Executado 2x:
```bash
uname -a
```

### ⚙️ Executado 2x:
```bash
cat /proc/cpuinfo
```

---

## 🔎 Análise Tática dos Ataques Capturados

1. **Reconhecimento de Hardware & OS:** Os comandos `uname -s -v -n -r -m` e `cat /proc/cpuinfo` servem para os robôs identificarem o número de núcleos de CPU e a arquitetura para baixar o binário correto de malware (ARM, x86 ou x64).
2. **Caça a Mineradores Concorrentes:** O comando `ps -ef | grep '[Mm]iner'` é clássico de campanhas de **Crypto-Jacking**. O bot procura se outro invasor já estava usando o servidor para minerar criptomoeda para 'matar' o processo rival e colocar o dele.
3. **Procura por MikroTik RouterOS:** O comando `/ip cloud print` tenta descobrir se o servidor é um roteador de borda MikroTik vulnerável.
4. **Teste de Shell Dropper:** O comando `printf "#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter` testa se o diretório local permite execução de scripts antes de baixar o payload principal.
