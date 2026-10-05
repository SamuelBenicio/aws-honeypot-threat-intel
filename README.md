# 🛡️ AWS Cowrie Honeypot & Threat Intelligence Pipeline

![AWS](https://img.shields.io/badge/AWS-Free%20Tier-orange?logo=amazon-aws)
![Terraform](https://img.shields.io/badge/IaC-Terraform-blueviolet?logo=terraform)
![Docker](https://img.shields.io/badge/Docker-Cowrie%20Honeypot-blue?logo=docker)
![Security](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-red)
![Python](https://img.shields.io/badge/Python-3.12-yellow?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

Um laboratório prático de **Engenharia de Detecção & Threat Intelligence** implementado na nuvem AWS, expondo intencionalmente uma porta SSH de engodo (*Honeypot Cowrie*) para atrair, registrar, conter e dissecar ataques cibernéticos reais da internet pública, mantendo **100% de elegibilidade ao Free Tier (custo zero)**.

---

## 🎯 1. Objetivo do Projeto

O objetivo deste projeto é desmistificar a segurança cibernética ofensiva e defensiva através de dados empíricos do mundo real:
* **Construir um sensor de inteligência de ameaças:** Capturar o tráfego hostil que varre a internet 24/7 sem colocar em risco qualquer ambiente corporativo ou pessoal.
* **Mapear táticas, técnicas e procedimentos (TTPs):** Compreender o que os robôs e agentes maliciosos fazem nos primeiros segundos após obterem acesso root em um servidor.
* **Engenharia de Nuvem Segura e Reprodutível:** Criar toda a infraestrutura através de **Infraestrutura como Código (Terraform)**, com controles rigorosos de menor privilégio (IAM), isolamento de containers e firewall de saída (*Egress filtering*).

---

## 💡 2. Por que o Projeto foi Feito?

A maioria dos cursos e tutoriais de segurança cibernética ensina a teoria ou utiliza ambientes de laboratório fechados e artificiais. Este projeto foi desenvolvido para:

1. **Testar a hipótese da "selva cibernética":** Quanto tempo leva para um endereço IP recém-criado na nuvem ser descoberto por atacantes?
2. **Entender a automação do crime digital:** Vivenciar na prática que ataques modernos não são hackers de capuz digitando manualmente, mas sim **enxames automatizados de botnets comerciais** competindo por poder computacional.
3. **Aplicar Defesa em Profundidade (*Defense in Depth*):** Aprender como expor intencionalmente um serviço vulnerável à internet mantendo o sistema hospedeiro e a rede externa 100% protegidos contra fugas de container (*container breakout*) ou abuso como pivô de ataques.

---

## 🏬 3. A Analogia: Site Tradicional vs. Honeypot

Para entender o funcionamento de um Honeypot, compare-o com um site convencional:

```
┌─────────────────────────────────────────────────────────────┐
│                       O SITE TRADICIONAL                    │
│   (Uma vitrine de vidro aberta no centro da cidade)         │
│                                                             │
│   • Público-alvo: Clientes legítimos.                       │
│   • Filosofia: "Seja bem-vindo, mas mantenha a ordem."      │
│   • Mecanismo de Defesa: Trancar portas, exigir senhas      │
│     fortes, colocar seguranças (WAF, Rate Limiting).        │
│   • Resposta a senhas erradas: Bloqueio imediato (401/403). │
└─────────────────────────────────────────────────────────────┘

                             VS

┌─────────────────────────────────────────────────────────────┐
│                       O HONEYPOT (ENGODO)                   │
│   (Uma casa com porta destrancada e um cofre de brinquedo)  │
│                                                             │
│   • Público-alvo: Exclusivamente invasores e criminosos.    │
│   • Filosofia: "Entre, fique à vontade... estamos filmando."│
│   • Mecanismo de Defesa: Paredes de concreto blindado       │
│     (Docker isolado), microfones e câmeras ocultas.         │
│   • Resposta a senhas erradas: ACEITA a senha de propósito  │
│     para manter o invasor ocupado e filmar suas táticas!    │
└─────────────────────────────────────────────────────────────┘
```

### No que os dois diferem fundamentalmente?

| Característica | Site Tradicional (Produção) | Honeypot (Armadilha) |
| :--- | :--- | :--- |
| **Objetivo do Tráfego** | Maximizar acessos legítimos. | Atrair exclusivamente tráfego malicioso. |
| **Política de Autenticação** | Recusar senhas incorretas e bloquear força bruta. | **Aceitar senhas fracas propositalmente** para induzir o atacante a prosseguir. |
| **Comportamento Pós-Login** | Executar regras de negócio e persistir no banco. | Simular um terminal falso em memória (*HoneyFS*) onde nada afeta o host real. |
| **Métrica de Sucesso** | Disponibilidade e integridade dos dados reais. | Riqueza de telemetria coletada (IPs, senhas, scripts, malwares). |

---

## 🧠 4. O que Aprendemos ao Deixar o Sistema Exposto?

Após deixar o Honeypot online por **~20 horas contínuas na AWS**, analisamos os logs brutos e extraímos aprendizados técnicos surpreendentes:

### A. A Velocidade da Descoberta
* Um IP público exposto na AWS **não passa despercebido por mais de 45 a 60 minutos**.
* Scanners globais de alta velocidade (como ZMap, Masscan, Censys e Shodan) varrem a internet IPv4 inteira na porta 22 continuamente.

### B. A "Guerra Subterrânea" de Cryptojacking
* Os invasores não estão necessariamente atrás de dados confidenciais; eles querem **poder computacional**.
* O comando mais frequente registrado nos logs foi:
  ```bash
  ps -ef | grep '[Mm]iner'
  ```
* **Aprendizado:** As botnets monitoram se *outros invasores* já infectaram a máquina. Se encontrarem processos de mineradores de Monero concorrentes (como `xmrig`), eles matam o processo rival para monopolizar 100% da CPU do seu servidor.

### C. Dicionários de Senhas Cirúrgicos
* As botnets não testam apenas `admin` e `123456`. Elas realizam ataques de força bruta voltados a componentes corporativos:
  - `elasticsearch` : `elasticsearch@1234` ➔ Caçando bancos de dados NoSQL expostos.
  - `frappe` : `frappe@123` ➔ Procurando sistemas ERP empresariais.
  - `azureuser` : `azureuser` ➔ Buscando máquinas virtuais mal configuradas na nuvem.
  - `backup` : `backup` ➔ Caçando rotinas de backup que guardam dados críticos.

### D. Tentativa Real de Implantação de Backdoor (Upload de 30.3 MB)
* O atacante `159.203.120.106` (DigitalOcean) conectou via **SFTP** e fez o upload de um executável de 30 MB chamado `sshd`.
* **Aprendizado:** O atacante tentou substituir o daemon legítimo do OpenSSH por uma versão adulterada (*Trojanized SSH*) para registrar senhas de futuros administradores e manter uma porta dos fundos (*backdoor*) permanente.

---

## 🏗️ 5. Arquitetura da Solução na AWS

```
[ Internet / Scanners / Botnets Mundiais ]
       │
       ▼ (Tentativas de invasão SSH na Porta 22)
┌─────────────────────────────────────────────────────────────┐
│ AWS VPC Dedicada (10.0.0.0/24)                              │
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
│   │       • HoneyFS em memória                          │   │
│   │       • Gravação de TTY, keystrokes e downloads     │   │
│   │                                                     │   │
│   │   [ Cron / Sincronizador Incremental de Logs ]      │   │
│   │    └─ Descarrega no S3 a cada 5 min via IAM Role    │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │ (Upload TLS sem chaves hardcoded)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Amazon S3 Bucket (cowrie-threat-intel-logs-*)               │
│  • Criptografia em repouso SSE-S3 AES-256                   │
│  • Acesso público 100% bloqueado                            │
│  • Ciclo de Vida: Expiração automática após 30 dias         │
│  • Particionamento: year=YYYY/month=MM/day=DD/*.json (Hive) │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔒 6. Defesa em Profundidade e Contenção de Riscos

Um honeypot mal projetado pode virar um vetor de ataque contra terceiros. Este projeto adotou **5 barreiras de isolamento**:

1. **Separação Rígida de Portas:** O SSH de gestão do Linux real roda na porta **22022**, restrita por firewall unicamente ao IP do administrador. A porta pública **22** conduz exclusivamente à armadilha.
2. **Hardening Docker Sem Privilégios:** O container Cowrie executa como usuário não-root (`UID 999`), descarta todas as capacidades do Linux (`cap_drop: ALL`) e impede escalonamento de privilégios (`no-new-privileges: true`).
3. **HoneyFS (Sistema de Arquivos Virtual):** Os comandos executados pelos atacantes (como `echo "hacked" > /tmp/payload`) operam em memória simulada; nenhum arquivo toca o disco real do sistema operacional host.
4. **Firewall Egress Restritivo (Anti-Botnet / Anti-Pivô):** O Security Group da AWS bloqueia conexões de saída arbitrárias (bloqueia porta 25 SMTP de spam e porta 22 de varredura externa), impedindo que a máquina seja utilizada como escravo de DDoS ou envio de phishing.
5. **Menor Privilégio no IAM (Zero Credenciais Expostas):** A máquina EC2 utiliza um *Instance Profile* com permissão estrita a `s3:PutObject` no bucket de logs, dispensando o armazenamento de chaves de API em arquivos locais.

---

## 📊 7. Métricas e Evidências Coletadas

Durante o monitoramento de ~20 horas, registramos:

* **Eventos Totais de Telemetria:** `1.615`
* **Endereços IP Únicos:** `36`
* **Tentativas de Autenticação Forçada:** `142`
* **Comandos Injetados no Terminal:** `78`
* **Arquivos Maliciosos Capturados:** `3 amostras`

### Principais Atores de Ameaça Identificados

| Endereço IP | Eventos | País / Cidade | Provedor / Tipo | Perfil de Ameaça |
| :--- | :--- | :--- | :--- | :--- |
| **`159.203.120.106`** | 9 | 🇺🇸 EUA (Clifton) | DigitalOcean | **Upload de Backdoor SSH (30.3 MB)** |
| **`178.208.88.6`** | 810 | 🇳🇱 Holanda (Amsterdam) | Iron Hosting | **Hospedagem Bulletproof (Botnet de Força Bruta)** |
| **`195.178.110.228`** | 56 | 🇦🇩 Andorra | Techoff SRV | **Infostealer (Caçador de sessões de Telegram e SMS 2FA)** |
| **`192.42.116.107`** | 10 | 🇳🇱 Holanda | Rede TOR | **Ataque mascarado por nó de saída da Dark Web** |
| **`54.153.51.142`** | 32 | 🇺🇸 EUA (San Jose) | AWS EC2 | **Servidor comprometido na própria nuvem AWS** |

> Para a análise técnica aprofundada comando a comando, consulte [INVESTIGACAO_FORENSE_AMEACAS.md](logs_salvos/INVESTIGACAO_FORENSE_AMEACAS.md) e o relatório analítico consolidado em [RELATORIO_THREAT_INTEL_REAL.md](logs_salvos/RELATORIO_THREAT_INTEL_REAL.md).

---

## 🧪 8. Suíte de Testes Automatizados (13 Validações)

O repositório contém uma suíte automatizada em Python ([`scripts/test_honeypot_suite.py`](scripts/test_honeypot_suite.py)) que atua como um invasor externo na internet validando todas as barreiras de segurança:

```powershell
python scripts/test_honeypot_suite.py
```

### 8.1 Testes Unitários e Especificações Estáticas (Offline & CI/CD)
O repositório possui uma suíte automatizada de **18 testes unitários e estáticos** em `tests/`, garantindo a confiabilidade dos parsers, conformidade das configurações do Docker e conformidade estrita da infraestrutura Terraform com padrões de segurança e menor privilégio (*Least Privilege*):

```bash
# Executando a suíte de testes unitários:
python -m unittest discover -s tests -p "test_*.py" -v
```

```text
test_cowrie_cfg_security_settings (test_cowrie_config.TestCowrieConfiguration) ... ok
test_cowrie_cfg_valid_ini (test_cowrie_config.TestCowrieConfiguration) ... ok
test_docker_compose_hardening (test_cowrie_config.TestCowrieConfiguration) ... ok
test_files_exist (test_cowrie_config.TestCowrieConfiguration) ... ok
test_userdb_structure (test_cowrie_config.TestCowrieConfiguration) ... ok
test_generate_markdown_report_formatting (test_log_parsers.TestLogParsers) ... ok
test_generate_text_log_formatting (test_log_parsers.TestLogParsers) ... ok
test_generate_threat_report_aggregation (test_log_parsers.TestLogParsers) ... ok
test_parse_cowrie_file_full_lifecycle (test_log_parsers.TestLogParsers) ... ok
test_parse_empty_and_corrupt_files (test_log_parsers.TestLogParsers) ... ok
test_ec2_root_volume_encrypted (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_example_tfvars_sanitized (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_gitignore_protects_sensitive_files (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_iam_least_privilege (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_s3_bucket_lifecycle_rules (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_s3_bucket_public_access_block (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_security_group_admin_port_isolation (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
test_variables_specification (test_terraform_spec.TestTerraformSecuritySpecs) ... ok
----------------------------------------------------------------------
Ran 18 tests in 0.080s - OK
```

### 8.2 Testes de Integração e Verificação em Tempo Real (Ambiente AWS)
Quando a instância na AWS está ativa, o script `scripts/test_honeypot_suite.py` executa **13 testes funcionais e de contenção ao vivo**:

```text
========================================================================
   SUÍTE DE TESTES E VERIFICAÇÃO DE SEGURANÇA DO HONEYPOT AWS
========================================================================
 [PASS] Porta 22 responde com banner SSH crível (OpenSSH Ubuntu)
 [PASS] Porta 22022 ativa para gestão do Administrador
 [PASS] Autenticação com credencial fraca aceita pelo Honeypot (Engodo)
 [PASS] Emulação de Sistema Operacional Crível (Hostname & Kernel)
 [PASS] Criação de arquivos no sistema simulado do Honeypot
 [PASS] Confinamento Absoluto: Arquivo do invasor NÃO toca o Host real
 [PASS] Hardening Docker: Container ativo e com restrição de privilégios
 [PASS] Bloqueio de Saída SMTP (Porta 25 - Anti-Spam Botnet)
 [PASS] Bloqueio de Varredura Externa (Porta 22 Outbound - Anti-Pivô)
 [PASS] Saída HTTPS Autorizada para APIs de Threat Intel e AWS
 [PASS] Auditoria JSON: Registro detalhado de logins e comandos
 [PASS] Execução do Script de Upload Incremental para o S3
 [PASS] Validação no Bucket S3: Telemetria armazenada na nuvem
========================================================================
RELATÓRIO FINAL: 13/13 Testes Aprovados (100.0% de Cobertura)
TODOS OS REQUISITOS DE SEGURANÇA E FUNCIONAMENTO FORAM VALIDADOS!
========================================================================
```

*(Total combinado: **31 testes automatizados** cobrindo segurança, integridade de dados e infraestrutura)*

---

## 🚀 9. Como Reproduzir o Projeto

### Pré-requisitos
* Conta na AWS com [AWS CLI](https://aws.amazon.com/cli/) autenticada (`aws configure`).
* [Terraform](https://www.terraform.io/) instalado localmente.
* Par de chaves SSH (ED25519) criado na AWS.

### Passo a Passo

```bash
# 1. Clone o repositório
git clone https://github.com/SEU_USUARIO/aws-honeypot-threat-intel.git
cd aws-honeypot-threat-intel

# 2. Configure as variáveis de infraestrutura
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Preencha seu IP público e o nome da sua chave SSH no terraform.tfvars

# 3. Provisione o ambiente com Terraform
terraform init
terraform plan
terraform apply -auto-approve

# 4. Conecte-se na porta administrativa
ssh -i /caminho/sua-chave.pem -p 22022 ubuntu@<IP_PUBLICO_EC2>

# 5. Inicie o Cowrie Honeypot
cd /home/ubuntu/cowrie
docker compose up -d

# 6. Para analisar e converter os logs salvos
python scripts/parse_logs.py logs_salvos/year=YYYY/month=MM/day=DD/cowrie_*.json
python scripts/generate_threat_report.py
```

---

## 📁 10. Estrutura de Diretórios

```plaintext
aws-honeypot-threat-intel/
├── .gitignore                      # Proteção de chaves privadas e segredos
├── PROJECT_SPEC.md                 # Especificação técnica original
├── README.md                       # Documentação técnica e arquitetura
├── cowrie/                         # Configuração e orquestração do Honeypot
│   ├── cowrie.cfg                  # Parametrização crível da emulação
│   ├── docker-compose.yml          # Container Docker com hardening e non-root
│   ├── sync_logs_to_s3.sh          # Exportador incremental de telemetria
│   └── userdb.txt                  # Dicionário de aceitação de credenciais
├── logs_salvos/                    # Telemetria real coletada durante a exposição
│   ├── INVESTIGACAO_FORENSE_AMEACAS.md # Análise forense de comandos e outputs
│   ├── RELATORIO_THREAT_INTEL_REAL.md  # Estatísticas consolidadas e geolocalização
│   └── year=2026/month=...         # Lotes brutos particionados em NDJSON
├── scripts/                        # Ferramentas e testes automatizados
│   ├── generate_threat_report.py   # Gerador de relatórios analíticos com GeoIP
│   ├── parse_logs.py               # Parser de JSON Lines para Markdown e Syslog
│   └── test_honeypot_suite.py      # Suíte de 13 testes de segurança e contenção
└── terraform/                      # Infraestrutura como Código (IaC)
    ├── ec2.tf                      # Instância EC2 t3.micro com script de boot
    ├── iam.tf                      # IAM Role e menor privilégio (s3:PutObject)
    ├── main.tf                     # Provedor AWS e versões
    ├── outputs.tf                  # Saídas de IPs, bucket e comandos
    ├── s3.tf                       # Bucket privado com criptografia e lifecycle
    ├── security_groups.tf          # Regras de firewall Ingress e Egress
    ├── terraform.tfvars.example    # Exemplo seguro de variáveis
    ├── variables.tf                # Declaração das variáveis do projeto
    └── vpc.tf                      # VPC, subnet pública e Internet Gateway
```

---

## 📄 Licença
Distribuído sob a licença MIT. Consulte `LICENSE` para mais detalhes.
