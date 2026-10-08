"""
Testes de Segurança, Compliance e Menor Privilégio
Valida as políticas de acesso e segurança operacional
"""

from pathlib import Path
import boto3

def test_gitignore_protects_secrets():
    """Garante que o arquivo .gitignore bloqueia segredos, chaves .pem e arquivos .tfvars"""
    gitignore_path = Path(__file__).parent.parent / ".gitignore"
    assert gitignore_path.exists(), "Arquivo .gitignore deve existir na raiz do projeto"

    content = gitignore_path.read_text(encoding="utf-8")
    assert "*.pem" in content
    assert "*.key" in content
    assert "*.tfvars" in content
    assert "*credentials*" in content
    assert "*secret*" in content

def test_lambda_function_configuration():
    """Valida se a função Lambda de enriquecimento está provisionada com runtime e memória corretos"""
    lambda_client = boto3.client("lambda", region_name="us-east-1")
    fn = lambda_client.get_function(FunctionName="cowrie-threat-intel-enricher")

    config = fn["Configuration"]
    assert config["Runtime"] == "python3.12"
    assert config["MemorySize"] == 128
    assert config["Timeout"] == 60
    assert config["Handler"] == "handler.lambda_handler"
    assert config["State"] == "Active"

def test_iam_grafana_reader_least_privilege():
    """Garante que o usuário do Grafana não possui permissões administrativas ou de deleção"""
    iam_client = boto3.client("iam", region_name="us-east-1")
    policies = iam_client.list_attached_user_policies(UserName="cowrie-threat-intel-grafana-reader")
    attached = policies["AttachedPolicies"]

    assert len(attached) >= 1
    policy_arn = attached[0]["PolicyArn"]

    policy_ver = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    doc = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_ver)["PolicyVersion"]["Document"]

    statements = doc["Statement"]
    all_actions = []
    for st in statements:
        assert st["Effect"] == "Allow"
        actions = st["Action"]
        if isinstance(actions, list):
            all_actions.extend(actions)
        else:
            all_actions.append(actions)

    # Nenhuma ação de deleção ou escrita administrativa permitida
    forbidden_actions = ["s3:DeleteObject", "athena:DeleteWorkGroup", "glue:DeleteTable", "iam:*", "*"]
    for act in all_actions:
        assert act not in forbidden_actions, f"Ação perigosa detectada na política do Grafana: {act}"
