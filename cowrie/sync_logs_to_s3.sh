#!/usr/bin/env bash
# ==============================================================================
# Script de sincronização de telemetria do Cowrie para o Amazon S3
# Utiliza a IAM Role vinculada à instância EC2 (Zero hardcoded credentials)
# ==============================================================================
set -euo pipefail

BUCKET_NAME="${1:-cowrie-threat-intel-logs-9628d6d2}"
LOG_FILE="/home/ubuntu/cowrie/var/log/cowrie/cowrie.json"
STATE_FILE="/home/ubuntu/cowrie/.sync_last_position"

if [ ! -f "${LOG_FILE}" ]; then
    echo "[!] Arquivo de log ${LOG_FILE} ainda não existe."
    exit 0
fi

DATE_PATH=$(date -u +"year=%Y/month=%m/day=%d")
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
TEMP_CHUNK="/tmp/cowrie_chunk_${TIMESTAMP}.json"

# Extrair novas linhas desde a última sincronização para envio eficiente
LAST_POS=0
if [ -f "${STATE_FILE}" ]; then
    LAST_POS=$(cat "${STATE_FILE}")
fi

TOTAL_LINES=$(wc -l < "${LOG_FILE}")

if [ "${TOTAL_LINES}" -gt "${LAST_POS}" ]; then
    TAIL_COUNT=$((TOTAL_LINES - LAST_POS))
    tail -n "${TAIL_COUNT}" "${LOG_FILE}" > "${TEMP_CHUNK}"
    
    TARGET_S3="s3://${BUCKET_NAME}/cowrie-logs/${DATE_PATH}/cowrie_${TIMESTAMP}.json"
    echo "[+] Enviando ${TAIL_COUNT} novas linhas de telemetria para ${TARGET_S3}..."
    aws s3 cp "${TEMP_CHUNK}" "${TARGET_S3}" --only-show-errors
    
    echo "${TOTAL_LINES}" > "${STATE_FILE}"
    rm -f "${TEMP_CHUNK}"
    echo "[OK] Sincronizacao concluida com sucesso."
else
    echo "[-] Nenhuma nova linha de log para sincronizar."
fi
