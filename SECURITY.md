# 🔒 Política de Segurança e Divulgação Responsável

## 1. Escopo e Finalidade do Projeto
Este repositório contém código e documentação para um **laboratório de pesquisa em cibersegurança e Threat Intelligence**.
Ele foi projetado especificamente para:
- Coletar telemetria de ataques reais em ambientes estritamente contidos.
- Estudar comportamentos maliciosos sem colocar em risco sistemas de produção ou terceiros.

---

## 2. Princípios de Segurança e Contenção Operacional
Ao implantar este projeto na AWS ou em qualquer outro provedor:
1. **Regras de Egress Restritivas:** O Security Group **nunca** deve permitir tráfego arbitrário de saída (como porta 25 SMTP de spam ou porta 22 de escaneamento externo).
2. **Isolamento de Containers:** O container Cowrie **não deve** ser executado em modo privilegiado (`privileged: true`) e **não deve** ter acesso ao socket do Docker (`/var/run/docker.sock`).
3. **Gestão de Segredos:** Nunca comite chaves privadas (`.pem`), arquivos `.tfstate` ou variáveis locais com IPs pessoais (`terraform.tfvars`) para repositórios públicos.

---

## 3. Relato de Vulnerabilidades
Se você encontrar qualquer vulnerabilidade de segurança neste código ou uma má configuração que possa permitir um *container escape*, por favor entre em contato de forma responsável:
- **E-mail:** `samuelrbenicio@gmail.com`
- Por favor, inclua um passo a passo detalhado ou Prova de Conceito (PoC) para reprodução.
