# Comparação inicial das duas arquiteturas

Objetivo: demonstrar o custo e o alcance de cada credencial antes de preparar a
apresentação ao gerente. Os resultados de execução ficam em [VALIDATION.md](VALIDATION.md).

| Dimensão | Compartilhada: esta pasta | Por instalação: raiz do repositório |
|---|---|---|
| Criação da chave privada | Servidor; a mesma chave é distribuída | Android Keystore em cada instalação |
| Transporte da chave | P12 e senha por HTTPS com pinning | Chave privada não é enviada; CSR/cadeia são públicos |
| Origem no Keystore | `IMPORTED` | `GENERATED` |
| Cópias anteriores ao Keystore | Servidor, demais instalações e memória de importação | Não há etapa de exportação/importação da chave do app |
| Validação de origem/proteção pelo servidor | Não há atestação desta chave; RASP **simulado** autoriza a entrega | Cadeia de atestação, raízes/status Google e política do banco |
| Identidade mTLS | Grupo de instalações que possui a mesma chave | Identidade individual da instalação cadastrada |
| Conta do usuário | Senha + TOTP e sessão própria | Senha + TOTP e sessão própria |
| Vínculo do token à chave | Vínculo ao fingerprint compartilhado; não distingue aparelhos | Vínculo à identidade individual cadastrada |
| Vazamento da chave | Atinge o grupo que usa a credencial; ainda são necessários os fatores/tokens exigidos pela aplicação | Atinge aquela identidade; comprometimento do app também pode permitir usar a chave sem extraí-la |
| Revogação | Revogar essa credencial afeta todas as cópias | Pode ser seletiva por identidade, conforme política implementada |
| Renovação/rotação | Não implementada neste v1; distribuição global precisa ser planejada | Renovação por mTLS + sessão, com política de atestação |
| Backend | Gestão de distribuição, segredo compartilhado e rotação; mais simples para autorizar o certificado | Cadastro/política individual, emissão, atestação e ciclo de vida |
| RASP real | Não integrado | Não integrado; atestação não equivale a RASP contínuo |

O servidor TLS não precisa manter uma cópia manual de toda chave pública de cliente
para validar mTLS. Ele valida certificados contra a CA confiável. Um banco normalmente
mantém registros de autorização, estado, vínculo com conta, revogação e auditoria por
instalação; essa gestão é diferente de uma exigência do protocolo de armazenar cada
chave pública separadamente. Nenhuma das duas arquiteturas justifica guardar chaves
privadas individuais dos clientes no backend.

Há uma diferença adicional entre os **labs atuais**: este novo app inclui pinning SPKI;
o anterior demonstra confiança na CA local e atestação, sem esse teste SPKI específico.
Pinning também pode ser usado com chaves geradas no cliente. Na comparação de uma
arquitetura de produção, mantenha equivalentes os controles de TLS/pinning, autenticação,
RASP e observabilidade; não atribua ao modelo de chave benefícios de controles externos.

## Demonstração sugerida

1. Mostrar o resultado `IMPORTED` e o fingerprint compartilhado no Xiaomi.
2. Mostrar principal/reserva aceitos e terceiro servidor recusado por pinning.
3. Bloquear o RASP simulado e verificar que não há nova entrega. Explicar que isso
   ainda não mede resistência real a root/Frida.
4. Fazer mTLS sem sessão e observar HTTP 401 para a conta.
5. Comparar duas entregas: mesma chave e mesmo certificado, com Keystores distintos.
6. Revogar a credencial compartilhada e observar a recusa para todas as cópias.
7. Abrir o outro app e mostrar chave `GENERATED`, atestação validada e renovação por mTLS.

**Conclusão técnica provisória:** credencial compartilhada pode acrescentar uma
barreira de acesso à API numa migração gradual. Ela comprova posse de uma chave
distribuída ao grupo, e não que a conexão vem de uma instalação única e íntegra.
Gerar a chave por instalação evita transportar o segredo privado e permite reduzir
o alcance de revogação/comprometimento. O esforço adicional concentra-se no cadastro
autorizado e no ciclo de vida; não basta comparar apenas quantidade de certificados.

Este laboratório não mede eficácia de RASP comercial, custo operacional em escala,
impacto em usuários ativos, recuperação após reinstalação ou indisponibilidade de
emissão. Esses pontos precisam de critérios e medições antes de uma recomendação de rollout.
