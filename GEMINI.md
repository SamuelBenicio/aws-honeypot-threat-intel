# Diretrizes e Regras do Projeto (Antigravity System Instructions)

Este documento define regras permanentes e mandatórias de desenvolvimento, governança e documentação para este repositório. O assistente de IA deve seguir estas diretrizes estritamente em todas as interações.

---

## 1. Regra Mandatória de Documentação (README.md)

* **Atualização Obrigatória do README.md:** Sempre que uma implementação for concluída (seja criação de novas funcionalidades, refatoração de código, alteração de infraestrutura Terraform, adição de painéis no Grafana, modificação de scripts ou expansão de testes), o arquivo `README.md` **DEVE OBRIGATORIAMENTE ser revisado e atualizado** antes da entrega final ao usuário e antes do envio ao GitHub.
* **Escopo da Atualização no README.md:**
  - Atualizar diagramas de arquitetura caso novos serviços, prefixos S3 ou tabelas tenham sido adicionados.
  - Documentar novos painéis, métricas ou consultas SQL adicionadas aos dashboards.
  - Explicar mecanismos de confiabilidade, resiliência ou salvaguardas FinOps introduzidas.
  - Atualizar a tabela de cobertura e contagem de testes automatizados (`pytest`).
  - Atualizar o mapa da estrutura de diretórios do repositório.

---

## 2. Padrões de Comunicação e Estilo

* **Proibição Estrita de Emojis:** É terminantemente proibido o uso de qualquer caractere emoji em respostas ao usuário, mensagens de commit do Git, comentários de código, documentações markdown (`README.md`, `PROJECT_SPEC.md`, etc.) e painéis do Grafana.
* **Tom e Linguagem:** Comunicação corporativa, técnica, formal e objetiva em língua portuguesa.
* **Transparência Técnica:** Apresentar relatórios objetivos com links clicáveis para arquivos e commits modificados.

---

## 3. Diretrizes de FinOps e Custo Zero

* **AWS Free Tier Estrito:** Toda e qualquer alteração de infraestrutura deve permanecer dentro da franquia gratuita da AWS (custo mensal projetado de US$ 0,00):
  - EC2: Instância `t3.micro` exclusiva.
  - S3: Políticas de ciclo de vida ativas com expiração de dados em até 60 dias.
  - Lambda: Alocação máxima de 128 MB a 256 MB de RAM e tempo de execução otimizado em paralelo.
  - Athena: Manutenção obrigatória do disjuntor financeiro de corte de escaneamento em 100 MB (`bytes_scanned_cutoff_per_query = 104857600`).

---

## 4. Garantia de Qualidade e Versionamento

* **Testes Automatizados:** Nenhuma implementação pode ser concluída sem a execução da suíte de testes (`pytest`) com 100% de aprovação e alta cobertura (>95%).
* **Sincronização Git:** Sempre que houver push para o GitHub, sincronizar tanto a branch de funcionalidade (`feat/*`) quanto a branch principal (`main`).
