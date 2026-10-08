"""
Testes de Integração com Serviços AWS: Amazon Athena, Glue Data Catalog e S3
Valida o ambiente ao vivo na nuvem AWS
"""

import time
import boto3
import pytest

@pytest.fixture(scope="module")
def athena_client():
    return boto3.client("athena", region_name="us-east-1")

@pytest.fixture(scope="module")
def glue_client():
    return boto3.client("glue", region_name="us-east-1")

@pytest.fixture(scope="module")
def s3_client():
    return boto3.client("s3", region_name="us-east-1")

def test_athena_workgroup_finops_limit(athena_client):
    """Valida se o Workgroup cowrie_analytics está ativo e com a trava de segurança de FinOps de 100MB"""
    wg = athena_client.get_work_group(WorkGroup="cowrie_analytics")
    status = wg["WorkGroup"]["State"]
    config = wg["WorkGroup"]["Configuration"]

    assert status == "ENABLED"
    assert config.get("EnforceWorkGroupConfiguration") is True

    # Trava de 100 MB em bytes = 104857600
    cutoff = config.get("BytesScannedCutoffPerQuery")
    assert cutoff == 104857600, f"Esperado teto de 104857600 bytes (100MB), obtido: {cutoff}"

def test_glue_database_and_table_exist(glue_client):
    """Valida se o banco de dados e a tabela externa existem no Glue Data Catalog"""
    db = glue_client.get_database(Name="cowrie_threat_intel")
    assert db["Database"]["Name"] == "cowrie_threat_intel"

    table = glue_client.get_table(DatabaseName="cowrie_threat_intel", Name="enriched_attacks")
    assert table["Table"]["Name"] == "enriched_attacks"
    assert table["Table"]["TableType"] == "EXTERNAL_TABLE"

    # Valida presença das colunas críticas para o Grafana
    column_names = [col["Name"] for col in table["Table"]["StorageDescriptor"]["Columns"]]
    assert "ip_address" in column_names
    assert "country_name" in column_names
    assert "latitude" in column_names
    assert "longitude" in column_names
    assert "login_attempts" in column_names
    assert "successful_logins" in column_names
    assert "passwords" in column_names
    assert "commands" in column_names

def test_athena_sql_execution(athena_client):
    """Executa uma query analítica real no Athena e valida o retorno"""
    query = "SELECT count(*) as total_attacks, count(DISTINCT country_name) as countries FROM enriched_attacks;"

    res = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": "cowrie_threat_intel"},
        WorkGroup="cowrie_analytics"
    )
    qid = res["QueryExecutionId"]

    # Aguarda término da execução (máx 15 segundos)
    for _ in range(15):
        time.sleep(1)
        status = athena_client.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if status in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break

    assert status == "SUCCEEDED"

    results = athena_client.get_query_results(QueryExecutionId=qid)
    rows = results["ResultSet"]["Rows"]
    assert len(rows) >= 2  # Cabeçalho + 1 linha de dados

    total_attacks = int(rows[1]["Data"][0]["VarCharValue"])
    countries = int(rows[1]["Data"][1]["VarCharValue"])

    assert total_attacks > 0, "A tabela enriched_attacks deveria conter registros minerados"
    assert countries > 0, "Deveriam existir países mapeados na tabela"
