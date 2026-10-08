import sys
from pathlib import Path
import pytest

# Adiciona os caminhos de código ao sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "lambda"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

@pytest.fixture
def sample_cowrie_raw_lines():
    """Gera um conjunto de linhas brutas de log do Cowrie para teste"""
    return [
        '{"eventid":"cowrie.session.connect","src_ip":"198.51.100.1","src_port":54321,"session":"s1","timestamp":"2026-10-08T12:00:00Z"}',
        '{"eventid":"cowrie.client.version","src_ip":"198.51.100.1","version":"SSH-2.0-libssh-0.7.0","session":"s1","timestamp":"2026-10-08T12:00:01Z"}',
        '{"eventid":"cowrie.login.failed","src_ip":"198.51.100.1","username":"root","password":"123","session":"s1","timestamp":"2026-10-08T12:00:02Z"}',
        '{"eventid":"cowrie.login.success","src_ip":"198.51.100.1","username":"admin","password":"admin","session":"s1","timestamp":"2026-10-08T12:00:03Z"}',
        '{"eventid":"cowrie.command.input","src_ip":"198.51.100.1","input":"uname -a","session":"s1","timestamp":"2026-10-08T12:00:04Z"}',
        '{"eventid":"cowrie.command.input","src_ip":"198.51.100.1","input":"cat /etc/passwd","session":"s1","timestamp":"2026-10-08T12:00:05Z"}',
        '{"eventid":"cowrie.session.file_download","src_ip":"198.51.100.1","shasum":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","destfile":"/tmp/payload.sh","session":"s1","timestamp":"2026-10-08T12:00:06Z"}',
        '{"eventid":"cowrie.session.closed","src_ip":"198.51.100.1","session":"s1","timestamp":"2026-10-08T12:00:07Z"}'
    ]
