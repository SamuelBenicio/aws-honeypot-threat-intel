#!/usr/bin/env python3
"""
Testes de conformidade e segurança da configuração do Cowrie:
- cowrie/cowrie.cfg
- cowrie/userdb.txt
- cowrie/docker-compose.yml
"""

import configparser
import os
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
COWRIE_DIR = ROOT_DIR / "cowrie"


class TestCowrieConfiguration(unittest.TestCase):
    def setUp(self):
        self.cfg_path = COWRIE_DIR / "cowrie.cfg"
        self.userdb_path = COWRIE_DIR / "userdb.txt"
        self.compose_path = COWRIE_DIR / "docker-compose.yml"

    def test_files_exist(self):
        """Garante que todos os arquivos de configuração necessários do Honeypot existem."""
        self.assertTrue(self.cfg_path.is_file(), "cowrie.cfg deve existir em cowrie/")
        self.assertTrue(self.userdb_path.is_file(), "userdb.txt deve existir em cowrie/")
        self.assertTrue(self.compose_path.is_file(), "docker-compose.yml deve existir em cowrie/")

    def test_cowrie_cfg_valid_ini(self):
        """Valida que o cowrie.cfg é um arquivo INI sintaticamente válido."""
        config = configparser.ConfigParser()
        # cowrie.cfg pode conter comentários sem espaçamento especial
        config.read(self.cfg_path, encoding="utf-8")

        self.assertIn("honeypot", config.sections())
        self.assertIn("ssh", config.sections())
        self.assertIn("telnet", config.sections())
        self.assertIn("output_jsonlog", config.sections())

    def test_cowrie_cfg_security_settings(self):
        """Valida diretrizes operacionais de segurança no cowrie.cfg."""
        config = configparser.ConfigParser()
        config.read(self.cfg_path, encoding="utf-8")

        # SSH deve estar ativo
        self.assertEqual(config.get("ssh", "enabled").lower(), "true")
        
        # Telnet deve estar desabilitado para focar em SSH
        self.assertEqual(config.get("telnet", "enabled").lower(), "false")

        # JSON log deve estar habilitado para SIEM/S3 pipeline
        self.assertEqual(config.get("output_jsonlog", "enabled").lower(), "true")
        self.assertIn("cowrie.json", config.get("output_jsonlog", "logfile"))

        # Prevenção do bug do Cowrie: 'compression' não pode estar setado como 'true'/'false' literal
        if config.has_option("ssh", "compression"):
            val = config.get("ssh", "compression").strip().lower()
            self.assertNotIn(val, ["true", "false"], "Não definir compression como true/false string para evitar quebra no handshake SSH")

    def test_userdb_structure(self):
        """Valida se o dicionário de senhas honeypot userdb.txt segue o padrão do Cowrie."""
        with open(self.userdb_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        self.assertGreater(len(lines), 0, "userdb.txt não deve estar vazio")

        for line in lines:
            parts = line.split(":")
            # Padrão cowrie: user:x:pass ou user:uid:pass ou user:x:*
            self.assertGreaterEqual(len(parts), 2, f"Linha inválida no userdb: '{line}'")
            username = parts[0]
            self.assertTrue(len(username) > 0, "Nome de usuário não pode ser vazio")

    def test_docker_compose_hardening(self):
        """Valida as travas de contenção do container Docker no docker-compose.yml."""
        with open(self.compose_path, "r", encoding="utf-8") as f:
            compose_text = f.read()

        # O container precisa dropar privilégios do kernel
        self.assertIn("cap_drop:", compose_text)
        self.assertIn("- ALL", compose_text)

        # Prevenção de escalonamento de privilégios
        self.assertIn("no-new-privileges:true", compose_text)

        # Configurações montadas como read-only
        self.assertIn(":ro", compose_text, "Arquivos de configuração devem ser montados em modo somente leitura (:ro)")

        # Porta do host mapeada para a porta interna 2222
        self.assertIn('"22:2222"', compose_text)


if __name__ == "__main__":
    unittest.main()
