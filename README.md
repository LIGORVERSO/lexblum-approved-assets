# Lexblum — centro de distribuição de conteúdo

Este repositório **público** distribui arquivos externos ao simulador Android privado. Não contém APK, código-fonte protegido, chave privada, dados de usuários nem conteúdo SOSL.

## Canais independentes

- **TESTES/engenharia:** MT, fixtures, cenários e modelos técnicos podem ser publicados como *prereleases* para validar o percurso real HTTPS → assinatura/hash → instalação → consumo → persistência/rollback. Não precisam de homologação autoral, mas exigem direito de redistribuição, rastreabilidade, ausência de segredos, integridade, identidade TESTES e isolamento de produção. Publicação pública significa que os bytes são acessíveis a terceiros.
- **PRODUÇÃO:** releases destinadas ao uso final exigem aprovação integral dos critérios aplicáveis, inclusive conteúdo material/visual/autoral quando pertinente. Nunca promover um teste por inferência.

Todos os pacotes Oga_PL e Lexblum_SDC são **externos ao APK**; MI internos e legados mínimos de migração não são releases de mundo.

## Contrato de entrega

Os assets de uma release usam `oga-catalog.envelope`, `sdc-catalog.envelope`, opcional `catalog.envelope` e objetos imutáveis nomeados pelo SHA-256. O consumidor valida Ed25519, hash, identidade, versão, compatibilidade e instalação transacional.

A arquitetura de TESTES em preparação usa `channels/testes.json` como ponteiro versionado para o *prerelease* completo, atualizado somente após auditoria e readback. O Worker existente resolve `/testes/...` a partir desse ponteiro, sem reconfiguração Cloudflare por revisão. O canal de produção mantém sua configuração própria.

**Estado atual:** a publicação automática, o ponteiro e o deploy do Worker modificado ainda requerem ativação e ensaio externo. A existência deste README não representa release publicada, workflow habilitado ou autonomia comprovada.

Autoridade de produto: [Controle Único](https://docs.google.com/document/d/1jHU_Nynz9tHIPYdWI1PyRba4OX16oSJhN7_FiX2EZkE/edit). Execução e pendências: [Issue #9](https://github.com/LIGORVERSO/lexblum-3d/issues/9).
