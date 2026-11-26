# Grype - Installer & Scanner — Azure DevOps Tasks

Extensão independente para Azure Pipelines, baseada na arquitetura da extensão [Trivy - Installer & Scanner](https://github.com/pitinga/azure-pipelines-tasks-trivy). **Não é um fork nem utiliza os identificadores do Trivy.**

- **GrypeInstaller@0:** instala Grype e Syft, detecta Windows/Linux/macOS e x64/ARM64, valida os checksums SHA-256 de releases oficiais, armazena em cache por versão/SO/CPU, e adiciona ambos ao PATH do job.
- **GrypeScan@0:** analisa imagens Docker/ACR, registries, diretórios, arquivos/JARs, SBOMs (Syft/SPDX/CycloneDX), archives OCI, PURL e CPEs. Expõe flags nativas e oferece, opcionalmente, geração de Syft JSON antes do scan.
- Executor **Node24 somente**, agente Azure Pipelines **>= 4.265.1**, sem dependências npm de runtime, instalado sem sudo. Extensão com manifesto **público** (`public: true`) na versão **0.1.3**. O status de publicação no Marketplace depende de seu processamento/validação.

## Uso básico

```yaml
- task: GrypeInstaller@0
  inputs:
    grypeVersion: latest
    syftVersion: latest

- task: GrypeScan@0
  inputs:
    sourceType: dir
    target: '$(Build.SourcesDirectory)'
    format: table
    failOn: high
    onlyFixed: true
```

Este exemplo reprova o job em vulnerabilidades **High ou Critical com correção**. Ao contrário do Trivy, Grype usa `--fail-on` e **retorna código 2** ao ultrapassar o limite. Sem `failOn`, o padrão é `none` (somente relatório). O scanner consulta/atualiza seu banco de vulnerabilidades automaticamente; o primeiro scan necessita acesso à Internet e pode ser lento.

## Installer

| Input | Padrão | Função |
| --- | --- | --- |
| `grypeVersion` | `latest` | Release estável do Grype ou versão fixa `0.122.1`. |
| `syftVersion` | `latest` | Release estável do Syft ou versão fixa `1.57.2`. |

A CLI Syft separada **não é requisito técnico para executar Grype diretamente**, pois Grype integra a biblioteca de catalogação Syft. O instalador a instala independentemente, para facilitar geração/reuso de SBOM e workflows comparativos.

O installer usa `$(Agent.ToolsDirectory)` (ou cache do usuário), faz cache por versão e plataforma, verifica SHA-256 do arquivo antes da extração e disponibiliza `GRYPE_PATH`, `GRYPE_VERSION`, `SYFT_PATH`, `SYFT_VERSION` e PATH às tasks seguintes **do mesmo job**. Não altera o sistema global. Se o asset não existir para o SO/CPU, retorna erro claro.

## GrypeScan: parâmetros CLI

| Input da task | CLI Grype | Comportamento |
| --- | --- | --- |
| `operation` | `grype`, `grype db ...` | `scan` (padrão) ou `dbCheck`, `dbUpdate`, `dbStatus`, `dbList`, `dbProviders`, `dbImport`, `dbDiff`, `dbSearch`. |
| `target` | `[IMAGE]` | Valor obrigatório no scan. Para scans de CPE/PURL individuais use `cpe:...` / `pkg:...`. |
| `sourceType` | esquema URI | `auto`, `docker`, `registry`, `podman`, `containerd`, `docker-archive`, `oci-archive`, `oci-dir`, `singularity`, `dir`, `file`, `sbom`. |
| `fromSources` | `--from` repetido | Precedência de fontes (ex.: docker,registry), uma por linha; exige sourceType=auto. |
| `workingDirectory` | pasta do processo | Diretório de execução da task. |
| `format` | `--output` | `table` (padrão), `json`, `sarif`, `cyclonedx`, `cyclonedx-json`, `template`. |
| `additionalFormats` | `--output` repetido | Formatos extras (um por linha). |
| `outputFile` | `--file` | Arquivo de relatório, vazio = stdout. |
| `failOn` | `--fail-on` | `none` (não reprova), `negligible`, `low`, `medium`, `high`, `critical`. |
| `byCve` | `--by-cve` | Prefere ID CVE quando possível. |
| `onlyFixed` | `--only-fixed` | Oculta vulnerabilidades sem correção. |
| `onlyNotFixed` | `--only-notfixed` | Oculta vulnerabilidades com correção. |
| `ignoreStates` | `--ignore-states` | `fixed,not-fixed,unknown,wont-fix`. |
| `addCpesIfNone` | `--add-cpes-if-none` | Gera CPE ausente. |
| `excludePaths` | `--exclude` | Glob, um por linha. |
| `scope` | `--scope` | `squashed`, `all-layers`, `deep-squashed`. |
| `sortBy` | `--sort-by` | `risk`, `package`, `severity`, `epss`, `kev`, `vulnerability`. |
| `platform` | `--platform` | Ex.: `linux/arm64`. |
| `distro` | `--distro` | Ex.: `alpine:3.20`. |
| `name` | `--name` | Nome do alvo. |
| `configFiles` | `--config` | Um arquivo por linha. |
| `profiles` | `--profile` | Um profile por linha. |
| `vexFiles` | `--vex` | Um arquivo por linha. |
| `template` | `--template` | Arquivo Go template; exige format `template`. |
| `showSuppressed` | `--show-suppressed` | Apenas saída `table`. |
| `quiet` | `--quiet` | Menos logs. |
| `verbose` | `-v`, `-vv` | Níveis 0, 1 ou 2. |
| `dbAutoUpdate` | `GRYPE_DB_AUTO_UPDATE` | `false` impede atualização automática. Banco deve existir localmente. |
| `dbCacheDir` | `GRYPE_DB_CACHE_DIR` | Diretório de cache do banco. |
| `generateSbom` | integração Syft | Gera SBOM `syft-json` antes da análise, opcional. |
| `sbomFile` | saída Syft | Caminho onde salvar a SBOM gerada. Vazio usa temporário e remove. |
| `additionalArguments` | flags extras | Tokens adicionais, com suporte a aspas e sem interpretação pelo shell. |

Consulte [documentação detalhada](docs/IMPLEMENTACAO.md) e [exemplos](examples/).

### Exemplo com SBOM

```yaml
- task: GrypeInstaller@0
- task: GrypeScan@0
  inputs:
    sourceType: dir
    target: '$(Build.SourcesDirectory)'
    generateSbom: true
    sbomFile: '$(Build.ArtifactStagingDirectory)/bom.syft.json'
    format: json
    outputFile: '$(Build.ArtifactStagingDirectory)/grype.json'
    failOn: critical
```

### Autenticação ACR e privacidade

Faça `Docker@2` `login` na service connection ACR **no mesmo job** antes do scan e use `sourceType: docker`. Para acessar remotamente uma registry sem Docker, use `sourceType: registry` e credenciais Docker/registry que Syft e Grype reconheçam. Segredos devem vir de variáveis secretas ou arquivos seguros, **não** de `additionalArguments`.

Não use `--insecure` nem tente adaptar flags do Trivy como `--severity`, `--ignore-unfixed`, `--exit-code`: **não existem nessa CLI do Grype**. A task sempre usa o comportamento nativo do Grype e suas flags documentadas.

### Limitações e validação

- `dbDelete` é destrutivo para o cache de banco; execute apenas quando intencional. `dbImport` exige target com caminho/URL do DB; `dbSearch` aceita opções específicas em `additionalArguments`.
- `latest` consulta a API GitHub a cada execução, podendo atingir rate limit. Para PROD, fixe versões do Grype e do Syft e mapeie `GITHUB_TOKEN` com segurança se necessário.
- CLI `--output template` exige template. `--show-suppressed` aceita somente table. `onlyFixed` e `onlyNotFixed` são mutuamente exclusivos.
- O catálogo de flags foi verificado no manual público do Grype; opções podem evoluir com versões futuras. Campos adicionais podem ser passados via `additionalArguments`.
- Instalação real e scan com banco online **ainda precisam de homologação num agente Azure DevOps**; testes de CI locais usam binários falsos para validar parâmetros e tratamento de erros. O código-fonte está preparado para build de VSIX; não foi publicado no Marketplace.

## Enviar o projeto ao GitHub

O repositório de destino é `pitinga/azure-pipelines-tasks-grype`, com branch `main`. Para quem possui **PowerShell 7**, Git e [GitHub CLI](https://cli.github.com/) autenticada (`gh auth login`), o script [`tools/Push-GrypeRepo.ps1`](tools/Push-GrypeRepo.ps1) cria o repositório (quando ainda não existe) e envia o código **em um único comando**, a partir da pasta extraída:

```powershell
./tools/Push-GrypeRepo.ps1
```

Por padrão, o repositório será público como o projeto Trivy, mas o VSIX permanece **privado** (`public: false` no manifesto). Para criar um repositório privado, use `./tools/Push-GrypeRepo.ps1 -Visibility private`. O script não solicita PAT nem cria releases, e não exclui branches. Depois do envio, valide [Actions](https://github.com/pitinga/azure-pipelines-tasks-grype/actions) antes de instalar ou compartilhar o VSIX.

## Desenvolvimento

```powershell
npm run check
npm run package:vsix
npm run verify:vsix
```

Workflows em `.github/workflows/validate-and-package.yml`: Node24 em Linux/Windows/macOS; empacotamento VSIX no Ubuntu, com artefato `grype-syft-vsix`.

## Validação com downloads oficiais no GitHub Actions

O workflow manual [smoke-real-downloads.yml](.github/workflows/smoke-real-downloads.yml) instala **Grype e Syft reais** a partir do GitHub Releases e verifica seus checksums SHA-256 e comandos `version` em Linux, Windows e macOS, sempre com Node 24. Por padrão, no Ubuntu também gera uma SBOM Syft JSON e executa um scan Grype com banco de vulnerabilidades real. Isso requer acesso à Internet para baixar executáveis e banco de dados e pode demorar mais que a pipeline de validação padrão. O workflow usa o token temporário `github.token` apenas para consultar a API de releases e não deve imprimir credenciais nos logs.

**Inicie manualmente em Actions → Smoke real Grype and Syft downloads → Run workflow**, depois da criação do repositório. O manifesto está público na versão 0.1.3; a publicação no Marketplace depende de credenciais e validação do publisher. Esse smoke test não substitui a homologação no agente Azure DevOps `devops-agent`.

## Referências

- CLI Grype: https://oss.anchore.com/docs/reference/grype/cli/
- Targets: https://oss.anchore.com/docs/guides/vulnerability/scan-targets/
- Instalação: https://oss.anchore.com/docs/installation/grype/
- Downloads Syft: https://github.com/anchore/syft/releases
- Downloads Grype: https://github.com/anchore/grype/releases

## Licença distribuída e validação

A versão técnica **0.1.1** inclui a licença MIT integral no VSIX e testa sua correspondência byte a byte com o repositório. Os GUIDs e as opções das tasks não foram alterados. A publicação pública usa uma versão patch da série 0.1.Y; a homologação funcional continua.

## Releases públicas 0.1.Y

As versões públicas seguem **`0.1.Y`**; somente o patch `Y` aumenta a cada release. O `@0` das tasks é a versão Major declarada em cada `task.json` e não muda quando o VSIX recebe outra versão. A GitHub Action `github-release.yml` publica uma GitHub Release independente do Marketplace, depois de CI aprovado. O workflow `publish-public.yml` permanece manual para o Marketplace, sem alterar tags ou releases. Sem esse segredo, o VSIX público pode ser enviado manualmente pelo publisher no [Marketplace](https://marketplace.visualstudio.com/manage). O GitHub Release público não significa, por si só, que a listagem do Marketplace já esteja pública.

### Nome comercial atualizado

A partir da versão pública **0.1.3**, a extensão usa o nome **Grype - Installer & Scanner**. O Syft permanece instalado pela task `GrypeInstaller@0`; apenas o nome comercial mudou. IDs, GUIDs e referências YAML existentes são preservados.

## GitHub Releases padronizadas

O workflow `.github/workflows/github-release.yml` e independente do Marketplace: exige CI aprovado na `main`, verifica o SHA, a identidade e a licenca do VSIX, cria tag `vX.Y.Z` imutavel e GitHub Release publica (nao draft nem pre-release) com VSIX. Reexecucoes preservam releases antigas. Marketplace e separado e manual.
