---
name: honeypot-pipeline-ops
description: >-
  Use this skill whenever auditing, diagnosing, deploying, testing, or troubleshooting
  the AWS Cowrie Honeypot Threat Intelligence and Malware Forensics pipeline across EC2,
  S3, AWS Lambda, Amazon Athena, and Grafana Cloud. It provides complete runbooks for
  self-healing synchronization validation, container health inspection, FinOps checks,
  test suite execution, mandatory README updates, and Git synchronization.
---

# Honeypot Pipeline Operations & Self-Healing Synchronization Skill

Este runbook operacional guia o diagnóstico, validação, manutenção e entrega de alterações no pipeline de Threat Intelligence do Cowrie Honeypot na AWS.

---

## 1. Visão Geral das Camadas do Pipeline

A integridade do pipeline depende do correto fluxo de dados entre 5 camadas:
1. **EC2 Cowrie Container:** Honeypot ativo na porta 22 (mapeada para 2222 interna), gravando em `var/log/cowrie/cowrie.json` via motor `jsonlog` com permissões UID 999.
2. **EC2 Cron Sincronizador (`sync_logs_to_s3.sh`):** Roda a cada 5 minutos via cron da conta `ubuntu`, monitora rotação por inode (`.sync_last_inode`), fatiamento determinístico via `sed -n` e watchdog de auto-recuperação do container.
3. **Amazon S3:** Ingestão desacoplada nos prefixos `cowrie-logs/` e `malware-samples/`.
4. **AWS Lambda (`cowrie-threat-intel-enricher`):** Processamento com leitura limitada a 10 MB, pré-aquecimento paralelo de GeoIP/AbuseIPDB, guardião de deadline (10s) e escrita prioritária em `enriched-telemetry/` e `enriched-malware/`.
5. **Amazon Athena & Grafana Cloud:** Consultas SQL sobre tabelas externas Glue com trava FinOps de 100 MB (`cowrie_analytics`) e painéis protegidos por `COALESCE`.

---

## 2. Diagnóstico Rápido de Sincronização

Para validar se o pipeline está saudável ou diagnosticar travamentos na sincronização:

### Passo 1: Executar Script de Diagnóstico Rápido
Execute o utilitário incluído nesta skill:
```bash
python .agents/skills/honeypot-pipeline-ops/scripts/check_pipeline_health.py
```

### Passo 2: Verificação Direta na EC2 via AWS SSM
Verifique o estado do container, permissões e cursores de sincronização:
```bash
aws ssm send-command \
  --instance-ids "i-0cbc1920d1c90e101" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["docker inspect -f \"Running={{.State.Running}}\" cowrie-honeypot", "cat /home/ubuntu/cowrie/.sync_last_position", "wc -l < /home/ubuntu/cowrie/var/log/cowrie/cowrie.json", "tail -n 20 /home/ubuntu/cowrie/cowrie-s3-sync.log"]'
```

### Passo 3: Verificação de Gatilhos e Erros na Lambda
Verifique se a função Lambda está sendo disparada sem erros:
```bash
aws lambda get-function --function-name cowrie-threat-intel-enricher
```

---

## 3. Matriz de Resolução de Problemas (Troubleshooting)

| Sintoma Observado | Causa Mais Provável | Procedimento de Correção |
| :--- | :--- | :--- |
| **Métricas congeladas no Grafana** | Motor `jsonlog` do Cowrie desativado por erro de permissão ou container parado. | O watchdog de auto-recuperação no `sync_logs_to_s3.sh` reinicia o container automaticamente em até 5 minutos. Para correção manual imediata: `chown -R 999:999 /home/ubuntu/cowrie/var` e `docker restart cowrie-honeypot`. |
| **Erros de SSH KEX nos logs do Cowrie** | Ausência do arquivo `/etc/ssh/moduli` na imagem do container. | Garantir que o volume `/etc/ssh/moduli:/etc/ssh/moduli:ro` esteja presente no `docker-compose.yml` da EC2. |
| **Painel de Força Bruta exibe "No data"** | Consulta SQL do Athena retornando `NULL` quando tabela está vazia. | Envolver a agregação com `COALESCE(sum(login_attempts), 0)` no JSON do dashboard. |
| **Timeout de 120s na AWS Lambda** | Lote com grande volume de novos IPs consultando GeoIP sequencialmente. | Certificar que `_prewarm_ip_caches` esteja usando `ThreadPoolExecutor` e que `_has_sufficient_time` force o fallback local se restarem menos de 10s. |
| **Crescimento excessivo de disco na EC2** | Arquivo `cowrie-s3-sync.log` acumulando saídas do cron. | O script `sync_logs_to_s3.sh` trunca automaticamente para 1.000 linhas ao atingir 5.000. |

---

## 4. Checklist Obrigatório para Qualquer Nova Implementação

Sempre que concluir qualquer alteração de código ou infraestrutura neste projeto:

1. **Testes Automatizados:**
   Execute a suíte de testes com cobertura:
   ```bash
   python -m pytest --cov=lambda --cov=scripts -q
   ```
   *Requisito:* 100% dos testes devem passar e a cobertura global deve permanecer >= 98%.

2. **Atualização do README.md (Mandatória):**
   Conforme definido em `GEMINI.md`, todo término de implementação exige atualização imediata do `README.md` refletindo novas arquiteturas, métricas, instruções operacionais e tabela de testes.

3. **Verificação de Custo Zero (FinOps):**
   - Nenhuma instância além de `t3.micro`.
   - Nenhuma retenção S3 superior a 60 dias sem lifecycle.
   - Nenhuma query no Athena sem a trava de 100 MB (`cowrie_analytics`).

4. **Sincronização Git Multi-Branch:**
   Efetuar commit e push tanto na branch de trabalho (`feat/*`) quanto na branch principal (`main`):
   ```bash
   git add .
   git commit -m "<tipo>(<escopo>): <mensagem sem emojis>"
   git push origin <branch-atual>
   git checkout main
   git merge <branch-atual>
   git push origin main
   git checkout <branch-atual>
   ```

5. **Regra de Emojis:**
   Garantir zero emojis em respostas, commits, arquivos e dashboards.
