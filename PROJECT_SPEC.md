# Blueprint do Projeto: Honeypot SSH na AWS com Pipeline de Threat Intelligence

## 1. Visão Geral do Projeto
Implementar um laboratório de cibersegurança e análise de ameaças na AWS, expondo intencionalmente uma porta SSH de engodo (*Honeypot*) para atrair varreduras, robôs e tentativas de força bruta da internet. 

Os eventos capturados serão ingeridos, armazenados em nuvem e processados por automações serverless para classificar a reputação dos IPs atacantes e gerar alertas automáticos.

## 2. Restrições e Ambiente
* **Provedor:** AWS (Região sugerida: `us-east-1` ou `sa-east-1`).
* **Orçamento:** AWS Free Tier / Créditos Promocionais (US$ 200 por até 6 meses).
* **Diretriz de Custo:** Utilizar instâncias elegíveis ao Free Tier (`t3.micro` ou `t4g.small`), armazenamento mínimo em EBS (8 GB a 20 GB gp3) e arquitetura serverless (Lambda e S3) para manter o custo mensal abaixo de US$ 2.
* **Segurança da Infraestrutura (CRÍTICO):** O honeypot não deve ser utilizado por atacantes como pivô para ataques externos. O Security Group e as regras de firewall do host devem restringir severamente o tráfego de saída (*egress*), permitindo apenas conexões para os serviços da AWS e APIs de reputação.

## 3. Arquitetura da Solução

```
[ Internet / Scanners / Atacantes ]
│
▼ (Tentativas SSH na porta 22)
[ Instância EC2 (t3.micro - Ubuntu) ]
- Cowrie Honeypot (Container Docker)
- Script agendado para export de logs
│
▼ (Upload periódico de logs JSON via TLS)
[ Amazon S3 Bucket ]
│
▼ (S3 Event Notification: s3:ObjectCreated:*)
[ AWS Lambda ]
- Parseia o log JSON do Cowrie
- Extrai IPs, credenciais testadas e comandos executados
- Consulta APIs de Reputação (AbuseIPDB / VirusTotal)
│
├──────────────────────────────┐
▼                              ▼
[ Discord / Telegram Bot ]        [ Amazon SNS / Email ]
(Alerta imediato de ataque)        (Relatório Diário/Semanal)
```

## 4. Componentes Técnicos

1. **Honeypot Host (EC2):**
   * SO: Ubuntu 24.04 LTS (instância `t3.micro`).
   * Software: **Cowrie SSH Honeypot** rodando isolado em container Docker.
   * Configuração de Portas:
     * Porta SSH real de administração: alterada para porta alta não padrão (ex: `22022`) com acesso restrito via Security Group apenas ao IP do administrador.
     * Porta SSH do Honeypot: porta `22` aberta para `0.0.0.0/0`.
2. **Armazenamento de Telemetria (Amazon S3):**
   * Bucket privado com bloqueio de acesso público habilitado (*Block Public Access*).
   * Política de ciclo de vida (*Lifecycle Rule*) para expiração após 30 dias para evitar acúmulo de dados.
3. **Análise de Ameaças Serverless (AWS Lambda):**
   * Runtime: Python 3.12.
   * Bibliotecas: `urllib3` / `requests`.
   * Integrações: API do **AbuseIPDB** e/ou **VirusTotal**.
4. **Notificação e Alertas:**
   * Webhook HTTP direto para canal do Discord/Telegram ou disparo via Amazon SNS.

## 5. Roteiro de Tarefas

- [ ] **Etapa 1: Infraestrutura como Código (Terraform) ou Scripts AWS CLI**
  - VPC, Subnet pública, Internet Gateway, Tabela de Roteamento.
  - Security Group: Egress restritivo, porta 22 pública (honeypot) e porta 22022 restrita (admin).
  - Bucket S3 privado com criptografia KMS/AES256 e lifecycle de 30 dias.
  - IAM Role + Instance Profile para EC2 com permissão estrita (`s3:PutObject` no bucket).
- [ ] **Etapa 2: Configuração e Deploy do Cowrie (Docker)**
  - `docker-compose.yml` para Cowrie isolado.
  - `cowrie.cfg` para simular ambiente crível.
  - Script de sincronização de logs para o S3 via cron/systemd.
- [ ] **Etapa 3: Desenvolvimento da Função Lambda**
  - Parser de eventos JSON do Cowrie (`cowrie.json`).
  - Desduplicação de IPs.
  - Consulta ao AbuseIPDB.
  - Webhook de notificação (Discord / Telegram).
- [ ] **Etapa 4: Hardening e Blindagem do Honeypot**
  - Regras de firewall no host (iptables/ufw) isolando o container contra conexões externas de saída.
  - AWS Budget alertando para gastos acima de US$ 5.
