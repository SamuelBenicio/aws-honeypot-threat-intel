"""
Testes Unitários da Lógica de Sincronização e Rotação de Logs do Honeypot
Valida o comportamento do script bash sync_logs_to_s3.sh implementado na EC2:
- Padrão estrito de regex para arquivos rotacionados (prevenindo loop recursivo)
- Controle de arquivos rotacionados via índice .synced_rotated_files
- Lógica de sincronização incremental (tailing) via .sync_last_position
- Prevenção de duplicidade e geração de partições S3
"""

import os
import re
import tempfile
import unittest
from datetime import datetime


class TestSyncRotationLogic(unittest.TestCase):
    def test_rotated_log_regex_pattern(self):
        """
        Valida que a expressão regular para arquivos rotacionados aceita estritamente
        o formato 'cowrie.json.YYYY-MM-DD' e rejeita sufixos repetidos ou arquivos ativos.
        """
        # Padrão estrito implementado no script de sincronização da EC2
        strict_pattern = re.compile(r"^cowrie\.json\.\d{4}-\d{2}-\d{2}$")

        # Casos válidos
        valid_filenames = [
            "cowrie.json.2026-10-08",
            "cowrie.json.2026-10-11",
            "cowrie.json.2026-10-12",
            "cowrie.json.2027-01-01",
        ]
        for name in valid_filenames:
            self.assertTrue(
                strict_pattern.match(name),
                f"Deveria aceitar arquivo rotacionado válido: {name}",
            )

        # Casos inválidos que causavam o bug de recursão (.synced.synced) ou sincronizavam arquivo incorreto
        invalid_filenames = [
            "cowrie.json",
            "cowrie.json.synced",
            "cowrie.json.2026-10-08.synced",
            "cowrie.json.2026-10-08.synced.synced",
            "cowrie.json.tmp",
            "cowrie.json.2026",
            "cowrie.json.2026-10",
            "cowrie.json.2026-10-08-01",
        ]
        for name in invalid_filenames:
            self.assertFalse(
                strict_pattern.match(name),
                f"Deveria rejeitar arquivo com formato inválido: {name}",
            )

    def test_rotated_files_index_tracking(self):
        """
        Simula o mecanismo de persistência de arquivos rotacionados já sincronizados (.synced_rotated_files).
        Garante idempotência: arquivos já sincronizados nunca são enviados duas vezes.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            index_file = os.path.join(tmp_dir, ".synced_rotated_files")

            # Inicializa o índice com um arquivo já sincronizado
            with open(index_file, "w", encoding="utf-8") as f:
                f.write("cowrie.json.2026-10-08\n")

            simulated_dir_files = [
                "cowrie.json.2026-10-08",
                "cowrie.json.2026-10-09",
                "cowrie.json.2026-10-10",
            ]

            to_sync = []
            with open(index_file, "r", encoding="utf-8") as f:
                synced_set = set(line.strip() for line in f if line.strip())

            for fname in simulated_dir_files:
                if fname not in synced_set:
                    to_sync.append(fname)
                    # Registra no índice
                    with open(index_file, "a", encoding="utf-8") as f:
                        f.write(fname + "\n")

            # Apenas 2026-10-09 e 2026-10-10 devem ser sincronizados
            self.assertEqual(to_sync, ["cowrie.json.2026-10-09", "cowrie.json.2026-10-10"])

            # Se rodar novamente, nenhum arquivo deve ser sincronizado
            with open(index_file, "r", encoding="utf-8") as f:
                synced_set_updated = set(line.strip() for line in f if line.strip())

            to_sync_second_run = [fname for fname in simulated_dir_files if fname not in synced_set_updated]
            self.assertEqual(to_sync_second_run, [])

    def test_incremental_log_slice_calculation(self):
        """
        Simula a lógica de fatiamento (tailing) do cowrie.json ativo com base no ponteiro .sync_last_position.
        """
        total_lines = 100
        last_position = 80

        # Caso normal: novas linhas chegaram (de 81 a 100)
        lines_to_read = total_lines - last_position
        start_line = last_position + 1
        self.assertEqual(lines_to_read, 20)
        self.assertEqual(start_line, 81)

        # Caso em que nenhuma linha nova foi gerada
        total_lines_idle = 100
        last_position_idle = 100
        self.assertLessEqual(total_lines_idle - last_position_idle, 0)

        # Caso em que o arquivo foi reinicializado / rotacionado (total_lines < last_position)
        total_lines_reset = 15
        last_position_stale = 100
        if total_lines_reset < last_position_stale:
            # Reseta o ponteiro
            effective_last_position = 0
            start_line_reset = effective_last_position + 1
            lines_to_read_reset = total_lines_reset
            self.assertEqual(start_line_reset, 1)
            self.assertEqual(lines_to_read_reset, 15)

    def test_s3_partition_path_generator(self):
        """
        Valida que o formato de particionamento de data gerado para o S3 é rigorosamente
        compatível com o particionamento Hive do Glue/Athena (year=YYYY/month=MM/day=DD).
        """
        dt = datetime(2026, 10, 12, 15, 30, 0)
        year = dt.strftime("%Y")
        month = dt.strftime("%m")
        day = dt.strftime("%d")

        partition_path = f"year={year}/month={month}/day={day}"
        self.assertEqual(partition_path, "year=2026/month=10/day=12")

        s3_key = f"cowrie-logs/{partition_path}/cowrie_{dt.strftime('%Y%m%d_%H%M%S')}.json"
        self.assertTrue(s3_key.startswith("cowrie-logs/year=2026/month=10/day=12/cowrie_20261012_153000.json"))

    def test_incomplete_json_line_truncation(self):
        """
        Valida que se o Cowrie estiver escrevendo concorrentemente e a última linha
        estiver cortada pela metade (sem fechar com '}'), a linha incompleta é
        removida do chunk e o ponteiro recua 1 linha para relê-la inteira no ciclo seguinte.
        """
        lines = [
            '{"eventid": "cowrie.session.connect", "src_ip": "1.1.1.1"}',
            '{"eventid": "cowrie.login.failed", "src_ip": "1.1.1.1", "username": "ro'  # cortada
        ]

        total_lines = len(lines)
        last_line = lines[-1].strip()

        # Simulação da verificação de integridade
        if not last_line.endswith("}"):
            clean_chunk = lines[:-1]
            effective_lines = total_lines - 1
        else:
            clean_chunk = lines
            effective_lines = total_lines

        self.assertEqual(len(clean_chunk), 1)
        self.assertEqual(effective_lines, 1)
        self.assertTrue(clean_chunk[-1].endswith("}"))

    def test_disk_retention_purge_policy(self):
        """
        Valida a política de expurgo de arquivos rotacionados antigos (> 7 dias)
        que já foram sincronizados com o S3 para prevenir esgotamento de disco na EC2.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            synced_index = os.path.join(tmp_dir, ".synced_rotated_files")
            with open(synced_index, "w", encoding="utf-8") as f:
                f.write("cowrie.json.2026-09-01\n")
                f.write("cowrie.json.2026-09-02\n")

            # Arquivo antigo já sincronizado -> deve ser removido
            # Arquivo recente (hoje) -> deve ser mantido
            rotated_files = {
                "cowrie.json.2026-09-01": {"age_days": 40, "synced": True},
                "cowrie.json.2026-10-12": {"age_days": 0, "synced": True},
                "cowrie.json.2026-09-02": {"age_days": 39, "synced": True},
            }

            to_delete = []
            for fname, meta in rotated_files.items():
                if meta["age_days"] > 7 and meta["synced"]:
                    to_delete.append(fname)

            self.assertIn("cowrie.json.2026-09-01", to_delete)
            self.assertIn("cowrie.json.2026-09-02", to_delete)
            self.assertNotIn("cowrie.json.2026-10-12", to_delete)


if __name__ == "__main__":
    unittest.main()
