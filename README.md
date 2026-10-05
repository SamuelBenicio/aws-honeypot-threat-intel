# 🛡️ AWS Cowrie Honeypot & Threat Intelligence Pipeline

![AWS](https://img.shields.io/badge/AWS-Free%20Tier-orange?logo=amazon-aws)
![Terraform](https://img.shields.io/badge/IaC-Terraform-blueviolet?logo=terraform)
![Docker](https://img.shields.io/badge/Docker-Cowrie%20Honeypot-blue?logo=docker)
![Security](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-red)
![Python](https://img.shields.io/badge/Python-3.12-yellow?logo=python)

Laboratório de **Engenharia de Detecção & Threat Intelligence** implementado na AWS, expondo intencionalmente uma porta SSH de engodo (*Honeypot Cowrie*) para capturar, armazenar e dissecar ataques cibernéticos reais da internet com **custo zero** (100% elegível ao AWS Free Tier).

---

## 🏗️ Arquitetura da Solução

```
[ Internet / Scanners / Botnets ]
       │
       ▼ (Tentativas SSH na Porta 22)
┌─────────────────────────────────────────────────────────────┐
│ AWS VPC (10.0.0.0/24)                                       │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ Security Group (Firewall Restritivo)                │   │
│   │  • Ingress: Porta 22 (0.0.0.0/0 - Pública)          │   │
│   │  • Ingress: Porta 22022 (Apenas IP do Admin)        │   │
│   │  • Egress:  Apenas HTTPS(443), HTTP(80) e DNS(53)   │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ Instância EC2 (t3.micro - Ubuntu 24.04 LTS / 8 GB)  │   │
│   │                                                     │   │
│   │   [ Host Linux Real ] ──► SSH Admin na Porta 22022  │   │
│   │                                                     │   │
│   │   [ Container Docker Isolado ]                      │   │
│   │    └─ Cowrie Honeypot (Escuta na Porta 22)          │   │
│   │       • Simula terminal corporativo Ubuntu          │   │
│   │       • Aceita senhas de dicionário de propósito    │   │
│   │       • Grava keystrokes, sessões e amostras        │   │
│   │                                                     │   │
│   │   [ Crontab / Sincronizador de Telemetria ]         │   │
│   │    └─ Sincronização S3 a cada 5 min via IAM Role    │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │ (Upload TLS sem credenciais expostas)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Amazon S3 Bucket (cowrie-threat-intel-logs-*)               │
│  • Criptografia em repouso AES-256                          │
│  • Acesso público 100% bloqueado                            │
│  • Ciclo de Vida: Exclusão automática após 30 dias          │
│  • Formato: year=YYYY / month=MM / day=DD / *.json (Hive)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Destaques de Engenharia e Segurança

* **Separação Rígida de Portas:** A porta pública `22` conduz exclusivamente ao container emulado do Cowrie. O SSH administrativo real roda na porta não padrão `22022`, restrita ao IP do operador.
* **Segurança Egress (Anti-Botnet / Anti-Pivô):** O firewall bloqueia tráfego arbitrário de saída (como porta 25 SMTP de spam e porta 22 de escaneamento externo), impedindo que a máquina seja utilizada como vetor de ataque secundário.
* **Zero Hardcoded Credentials:** A instância comunica-se com o Amazon S3 utilizando uma **IAM Role & Instance Profile** com privilégio restrito a `s3:PutObject`.
* **Hardening Docker:** Execução sem privilégios de root (`UID 999`), descarte total de capacidades (`cap_drop: ALL`) e prevenção de escalonamento (`no-new-privileges: true`).
* **Particionamento Hive:** Logs organizados em `year=YYYY/month=MM/day=DD/` prontos para ingestão por ferramentas de Data Lake como AWS Athena e AWS Glue.

---

## 📊 Resultados Reais Coletados (~20h de Exposição)

Durante o período de monitoramento, o laboratório capturou **1.615 eventos de ataque real**:

| Indicador | Quantidade |
| :--- | :--- |
| **Eventos Registrados** | **1.615** |
| **IPs Únicos de Atacantes** | **36** |
| **Tentativas de Força Bruta (Brute-Force)** | **142** |
| **Comandos Injetados no Terminal** | **78** |
| **Binários Maliciosos Capturados** | **3 amostras** (incluindo 1 backdoor de 30.3 MB) |

### Top Atores de Ameaça Identificados

* **`159.203.120.106` (EUA / DigitalOcean):** Conectou via SFTP e fez upload de um backdoor de 30.3 MB (`sshd`) para substituir o daemon legítimo e manter persistência furtiva.
* **`178.208.88.6` (Holanda / Bulletproof Hosting):** Responsável por **810 ataques** automatizados procurando usuários de infraestrutura (`deploy`, `hadoop`, `steam`).
* **`195.178.110.228` (Andorra):** Disparou scripts vasculhando sessões do **Telegram Desktop (`tdata`)** e modems de celular para roubo de códigos SMS de verificação 2FA.
* **`192.42.116.107` (Nó de Saída TOR):** Atacante tentando ocultar completamente a origem através da rede Onion.

Consulte a investigação completa em [INVESTIGACAO_FORENSE_AMEACAS.md](logs_salvos/INVESTIGACAO_FORENSE_AMEACAS.md) e [RELATORIO_THREAT_INTEL_REAL.md](logs_salvos/RELATORIO_THREAT_INTEL_REAL.md).

---

## 🔬 Táticas MITRE ATT&CK® Observadas

* **T1082 (System Information Discovery):** Scripts complexos mapeando núcleos de CPU (`nproc`), arquitetura (`uname -m`) e presença de GPU Nvidia (`lspci | grep nvidia`).
* **T1057 (Process Discovery) / T1496 (Resource Hijacking):** Comandos caçando mineradores de criptomoeda concorrentes (`ps -ef | grep '[Mm]iner'`) para matá-los e monopolizar recursos.
* **T1552 (Unsecured Credentials):** Varreduras atrás de sessões ativas do Telegram (`tdata`).
* **T1059.004 (Unix Shell):** Testes de permissão de escrita/execução em pastas temporárias (`printf "..." > filter && ./filter`).
* **T1556.004 (Modify Authentication Process):** Tentativa de sobreposição do binário OpenSSH oficial por versão trojanizada.

---

## 🧪 Suíte de Testes Automatizados

O repositório inclui uma suíte completa de **13 testes automatizados** em Python que simulam invasões externas e validam as barreiras de contenção:

```powershell
python scripts/test_honeypot_suite.py
```

```text
========================================================================
RELATÓRIO FINAL: 13/13 Testes Aprovados (100.0% de Cobertura)
TODOS OS REQUISITOS DE SEGURANÇA E FUNCIONAMENTO FORAM VALIDADOS!
========================================================================
```

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
* Conta na AWS com [AWS CLI](https://aws.amazon.com/cli/) autenticada (`aws configure`).
* [Terraform](https://www.terraform.io/) instalado.

### 1. Provisionar Infraestrutura com Terraform
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edite o terraform.tfvars com seu IP público e nome da sua chave SSH
terraform init
terraform plan
terraform apply
```

### 2. Deploy do Cowrie Honeypot
Conecte-se na porta de administração:
```bash
ssh -i /caminho/sua-chave.pem -p 22022 ubuntu@<IP_PUBLICO>
```
Suba o container e configure o agendador de logs:
```bash
cd /home/ubuntu/cowrie
docker compose up -d
```

### 3. Parse e Análise de Logs
Para converter logs brutos em relatórios legíveis:
```bash
python scripts/parse_logs.py logs_salvos/year=YYYY/month=MM/day=DD/cowrie_*.json
python scripts/generate_threat_report.py
```

---

## 📁 Estrutura de Arquivos

```plaintext
aws-honeypot-threat-intel/
├── cowrie/                         # Configuração e orquestração do Honeypot
│   ├── cowrie.cfg                  # Parametrização crível do ambiente
│   ├── docker-compose.yml          # Container isolado com hardening
│   ├── userdb.txt                  # Dicionário de aceitação de credenciais
│   └── sync_logs_to_s3.sh          # Exportador incremental para o Amazon S3
├── logs_salvos/                    # Telemetria real coletada
│   ├── INVESTIGACAO_FORENSE_AMEACAS.md # Análise forense detalhada de comandos
│   ├── RELATORIO_THREAT_INTEL_REAL.md  # Estatísticas consolidadas e geolocalização
│   └── year=2026/month=...         # Lotes de telemetria brutos (NDJSON)
├── scripts/                        # Ferramentas e testes automatizados
│   ├── generate_threat_report.py   # Gerador analítico com geolocalização
│   ├── parse_logs.py               # Parser de JSON Lines para Markdown/Syslog
│   └── test_honeypot_suite.py      # Suíte de 13 testes de segurança
└── terraform/                      # Infraestrutura como Código (IaC)
    ├── ec2.tf                      # Instância e script de bootstrap
    ├── iam.tf                      # Políticas e perfis de menor privilégio
    ├── main.tf                     # Provedores e configuração backend
    ├── outputs.tf                  # Dados exportados
    ├── s3.tf                       # Armazenamento criptografado e lifecycle
    ├── security_groups.tf          # Regras de firewall Ingress/Egress
    ├── variables.tf                # Variáveis parametrizáveis
    └── vpc.tf                      # Rede pública dedicada
```

---

## 📄 Licença
Distribuído sob a licença MIT. Consulte `LICENSE` para mais informações.
