# Implementação, compatibilidade e critérios de homologação

## Arquitetura

- Duas tasks independentes `GrypeInstaller@0` e `GrypeScan@0` em Node 24; cada diretório contém seu `index.js` e uma cópia local de bibliotecas CommonJS. Dependências do `node_modules` não são embutidas.
- Installer consulta releases oficiais Anchore, determina os assets (`grype_...` e `syft_...`), baixa `.tar.gz`/`.zip`, verifica SHA-256, extrai somente o binário em Linux/macOS, extrai pacote ZIP via PowerShell no Windows e marca o cache como verificado.
- Scanner recebe opções como array de argumentos com `spawn(..., {shell:false})`, impedindo interpretação de operadores de shell no target.
- Detecção de plataforma: `process.platform` `linux`, `darwin`, `win32`; `process.arch` `x64`, `arm64`. Assets só são aceitos se existirem na release.
- CLI `--fail-on high` retorna código de saída 2 quando vulnerabilidades relevantes estão presentes; qualquer código não zero marca task como falha.

## Diferenças em relação ao Trivy

| Trivy | Grype |
| --- | --- |
| `TrivyInstaller@0` | `GrypeInstaller@0` instala **Grype + Syft** |
| `TrivyScan@0` | `GrypeScan@0` |
| `--exit-code` | `--fail-on` (código 2 para vulnerabilidade acima do limiar) |
| `--ignore-unfixed` | `--only-fixed` ou `--ignore-states not-fixed,unknown,wont-fix` |
| `--severity HIGH,CRITICAL` | Não há filtro de severidades equivalente no CLI principal: `--fail-on high` configura *gating*, não remove resultados de baixa severidade |
| `--format json` | `--output json` |
| `--output arquivo` | `--file arquivo` |
| `--skip-db-update` | `GRYPE_DB_AUTO_UPDATE=false` |
| `image` / `fs` como subcomandos | Argumento `target` com prefixos `docker:`, `dir:`, `sbom:` ou `--from` |

## Estratégia de segurança

- Nenhuma execução automática de scripts remotos `curl | sh`.
- Apenas URLs GitHub oficiais `github.com`, `api.github.com` e redirecionamentos para `*.githubusercontent.com`.
- SHA-256 conferido contra o arquivo de checksums oficial daquela release.
- Scripts usam `spawn` sem shell e `PATH` de job, sem privilégios globais.
- Versão estável estrita. Não instala pré-release.
- Cache do agente reutilizado por ferramenta, versão, SO e arquitetura.
- O token `GITHUB_TOKEN` é utilizado somente em chamadas API; não é enviado ao CDN.

## Homologação necessária antes de publicação

1. Instalar versões fixas e `latest` no Ubuntu 24.04 x64 e verificar `grype version`/`syft version`.
2. Reexecutar para validar cache, variáveis e PATH entre tasks do mesmo job.
3. Testar Windows x64 e macOS arm64 na matrix com downloads reais (não apenas testes de mocks).
4. Fazer scan de `dir:.`, imagem Docker/ACR, SBOM Syft JSON e JAR usando `file:` ou diretório.
5. Verificar `format: table/json/sarif`, arquivo de saída, Syft SBOM, output/artefatos.
6. Validar `failOn: none` e `failOn: high`, com exit status 2 para findings.
7. Validar `onlyFixed`, `ignoreStates`, `excludePaths`, VEX, arquivos de configuração, banco offline.
8. Publicar VSIX inicialmente como privado e executar smoke test no Azure Pipelines real.
9. Após homologação, definir versão de publicação, atualizar README e configurar tag + GitHub Release com VSIX.

## GitHub

O diretório foi preparado para o futuro repositório `pitinga/azure-pipelines-tasks-grype`, branch `main`, mas **não pressupõe que o repositório já exista**.
