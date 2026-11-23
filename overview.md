# Grype & Syft — Azure Pipelines

Extensão independente com duas tasks Node24 para instalar os scanners Anchore e analisar vulnerabilidades.

- **GrypeInstaller@0**: downloads oficiais do Grype e Syft com verificação SHA-256 e cache por SO/arquitetura. Suporte a `latest` ou versões fixas.
- **GrypeScan@0**: scans de imagens, diretórios, arquivos, registries e SBOMs. Opções nativas como `--fail-on`, `--only-fixed`, `--by-cve`, `--output`, `--file`, `--vex`, `--exclude`.

```yaml
- task: GrypeInstaller@0
  inputs:
    grypeVersion: latest
    syftVersion: latest

- task: GrypeScan@0
  inputs:
    sourceType: dir
    target: '$(Build.SourcesDirectory)'
    format: json
    outputFile: '$(Build.ArtifactStagingDirectory)/grype.json'
    failOn: high
    onlyFixed: true
```

**Requer agente Azure Pipelines >= 4.265.1 (Node24).** Não contém credenciais, não exige sudo e não executa scripts de instalação de terceiros. Para ACR, autentique-se antes no mesmo job. `--fail-on` retorna código 2 quando o limiar configurado é atingido.

Documentação, parâmetros e exemplos: https://github.com/pitinga/azure-pipelines-tasks-grype
