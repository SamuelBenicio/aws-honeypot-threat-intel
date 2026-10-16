# Runbook de Operacoes, Diagnostico e Troubleshooting do Pipeline Honeypot

Este documento estabelece os procedimentos operacionais padrao (SOP), diagnostico e resolucao de incidentes para o pipeline de Threat Intelligence e Forense de Malware do Cowrie Honeypot na nuvem AWS.

---

## 1. Visao Geral da Cadeia de Custodia e Dados

O pipeline opera com cinco estagios de processamento desacoplados:
1. **Ponto de Ingestao (Host EC2 / Cowrie Honeypot):**
   - Container Docker isolado executando como UID 999.
   - Porta TCP/22 externa mapeada para a porta interna 2222 do Cowrie.
   - OpenSSH de administracao real movido para a porta TCP/22022.
   - Arquivo de log ativo em `/home/ubuntu/cowrie/var/log/cowrie/cowrie.json`.
   - Quarentena local de binarios em `/home/ubuntu/cowrie/var/lib/cowrie/downloads/`.
2. **Sincronizador em Lote (`sync_logs_to_s3.sh` via Cron):**
   - Execucao a cada 5 minutos pelo cron da conta `ubuntu`.
   - Trava atomica de execucao concorrente via `flock` (`/home/ubuntu/cowrie/.sync.lock`).
   - Rastreamento de cursor de linha (`.sync_last_position`) e identificador de inode (`.sync_last_inode`).
   - Fatiamento deterministico de linhas via `sed -n "${START_LINE},${TOTAL_LINES}p"`.
   - Watchdog de auto-recuperacao com reinicio preventivo se o motor `jsonlog` falhar.
3. **Armazenamento de Objeto (Amazon S3):**
   - Ingestao de logs brutos em `cowrie-logs/year=YYYY/month=MM/day=DD/`.
   - Ingestao de amostras de malware em `malware-samples/<sha256>`.
   - Politicas de ciclo de vida (Lifecycle Rules) configuradas para expuracao automatica em 60 dias.
4. **Camada de Processamento Serverless (AWS Lambda):**
   - Funcao: `cowrie-threat-intel-enricher` (Python 3.12, 128 MB de RAM, Timeout 120s).
   - Enriquecimento paralelo via `ThreadPoolExecutor` para GeoIP e AbuseIPDB.
   - Inspecao estatica autonoma de executaveis (ELF, PE, Scripts Shell) e integracao VirusTotal v3.
   - Guardiao de deadline (`context.get_remaining_time_in_millis() < 10000`) para garantir gravacao no S3.
   - Gravacao em JSON Lines compativel com OpenX JsonSerDe em `enriched-telemetry/` e `enriched-malware/`.
5. **Camada Analitica e Visualizacao (Amazon Athena & Grafana Cloud):**
   - Banco de dados Glue Catalog: `cowrie_threat_intel`.
   - Workgroup FinOps: `cowrie_analytics` com disjuntor de corte em 100 MB (`bytes_scanned_cutoff_per_query`).
   - Painel SOC Grafana Cloud com auto-refresh de 5 minutos alinhado a cadencia do cron.

---

## 2. Procedimento Padrao de Diagnostico e Health Check

Para inspecionar a integridade de todas as camadas simultaneamente, execute o utilitario de diagnostico:

```bash
python scripts/check_pipeline_health.py
```

O utilitario aceita argumentos de linha de comando ou variaveis de ambiente para ambientes dinâmicos de CI/CD:

```bash
python scripts/check_pipeline_health.py --instance-id i-0cbc1920d1c90e101 --bucket cowrie-threat-intel-logs-9628d6d2 --region us-east-1
```

O script retorna exit code semantico (`0` para sucesso integral e `1` em caso de degradacao de qualquer camada), permitindo integracao direta em pipes de monitoramento.

### O que o script valida:
* **Conectividade e Autenticacao IAM:** Valida as credenciais ativas via AWS STS.
* **Acessibilidade do Bucket S3:** Confirma se o bucket existe e se contem arquivos recentes em `cowrie-logs/` e `enriched-telemetry/`.
* **Configuracao da Lambda:** Inspeciona status, runtime, limites de memoria e tempo de timeout.
* **Trava FinOps do Athena:** Valida se o workgroup `cowrie_analytics` esta ativo com o limite de 100 MB aplicado.
* **Telemetria Direta do Host EC2 (via AWS SSM):**
  - Confirma se o container `cowrie-honeypot` esta em execucao (`Running=true`).
  - Compara a posicao do cursor (`STATE_POS`) com o total de linhas do arquivo de log (`TOTAL_LINES`). Se ambos forem iguais, a sincronizacao esta 100% em dia.

---

## 3. Matriz de Troubleshooting e Recuperacao de Falhas

### Cenario 1: Metricas congeladas no painel do Grafana
* **Sintoma:** O dashboard exibe valores antigos ou nao reflete novos acessos da internet.
* **Causa Raiz 1:** Container parado ou motor `jsonlog` desativado por conflito de permissoes.
* **Causa Raiz 2:** Cursor de sincronizacao preso em arquivo rotacionado.
* **Procedimento de Recuperacao:**
  1. Conecte a instancia via AWS Systems Manager Session Manager:
     ```bash
     aws ssm start-session --target i-0cbc1920d1c90e101
     ```
  2. Verifique os logs do container Cowrie:
     ```bash
     docker logs --tail 30 cowrie-honeypot
     ```
  3. Caso haja a mensagem `Failed to load output engine: jsonlog`, o watchdog corrigira automaticamente em ate 5 minutos. Para recuperacao manual imediata:
     ```bash
     sudo chown -R 999:999 /home/ubuntu/cowrie/var
     sudo chmod -R a+rwX /home/ubuntu/cowrie/var
     docker restart cowrie-honeypot
     ```
  4. Force a execucao do sincronizador e confira a saida:
     ```bash
     su - ubuntu -c "/home/ubuntu/cowrie/sync_logs_to_s3.sh"
     ```

---

### Cenario 2: Quedas de conexao SSH antes da autenticacao (Handshake KEX)
* **Sintoma:** Scanners e robos conectam na porta 22 mas encerram a sessao imediatamente antes de tentar login.
* **Causa Raiz:** Ausencia de numeros primos para o algoritmo `diffie-hellman-group-exchange-sha256` na imagem base do container.
* **Procedimento de Recuperacao:**
  1. Verifique se `/etc/ssh/moduli` esta montado no `docker-compose.yml`:
     ```yaml
     volumes:
       - /etc/ssh/moduli:/etc/ssh/moduli:ro
     ```
  2. Reinicie o compose:
     ```bash
     cd /home/ubuntu/cowrie && docker compose up -d
     ```

---

### Cenario 3: Painel de Forca Bruta exibindo "No data"
* **Sintoma:** Card de Tentativas de Acesso (Forca Bruta) fica em branco ou exibe erro quando nao ha eventos no periodo.
* **Causa Raiz:** A consulta SQL retorna `NULL` quando a soma nao encontra registros correspondentes ao filtro de tempo.
* **Procedimento de Recuperacao:**
  - Garanta que a consulta SQL utilize a expressao `COALESCE`:
    ```sql
    SELECT coalesce(sum(login_attempts), 0) as total_tentativas FROM enriched_attacks;
    ```

---

### Cenario 4: Alertas de Timeout de 120s na Funcao Lambda
* **Sintoma:** Execucoes da Lambda atingem 120 segundos no CloudWatch e o arquivo `enriched_*.json` nao e gerado.
* **Causa Raiz:** Lote grande contendo dezenas de enderecos IP ineditos executando consultas externas de GeoIP e AbuseIPDB sequencialmente.
* **Procedimento de Recuperacao:**
  1. Valide se a funcao `_prewarm_ip_caches` esta ativada com `ThreadPoolExecutor(max_workers=10)` em `lambda/handler.py`.
  2. Confirme que a funcao `_has_sufficient_time` aborta consultas de rede quando o tempo restante for inferior a 10 segundos.

---

## 4. Checklist de Liberacao de Mudancas (SRE Release Gate)

Antes de promover qualquer alteracao de infraestrutura ou codigo para o ambiente em producao:

1. **Execucao da Suite de Testes:**
   ```bash
   python -m pytest --cov=lambda --cov=scripts -q
   ```
   *Criterio de Aprovacao:* 100% dos testes aprovados e cobertura global >= 98%.
2. **Auditoria Estatica de Seguranca (IaC):**
   Confirmar que o arquivo `terraform/terraform.tfvars` permanece fora do Git e que as regras de isolamento de rede nao foram afrouxadas.
3. **Validacao de FinOps:**
   Confirmar que nenhuma consulta ou recurso adicional desrespeite os limites da camada gratuita da AWS.
4. **Atualizacao da Documentacao:**
   Atualizar o arquivo `README.md` refletindo eventuais mudancas na arquitetura, contagem de paineis ou metricas de testes.
