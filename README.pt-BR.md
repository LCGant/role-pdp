# Servico PDP

[Read in English](README.md) | [Raiz do projeto](../../README.pt-BR.md)

`role-pdp` e o Policy Decision Point centralizado. Ele responde se um sujeito pode executar uma acao sobre um recurso dentro do contexto atual.

## Escopo principal

- decisoes centralizadas de autorizacao
- avaliacao de RBAC com awareness de tenant
- decisoes por ownership
- obrigacoes de step-up e reauth
- APIs admin para policy e cache
- encaminhamento de auditoria de decisoes para `audit`

## Intencao de desenho

O PDP e infraestrutura interna. Ele deve ser chamado apenas por servicos confiaveis, nunca por clientes publicos.

Ele e separado da autenticacao de forma intencional:

- `auth` prova quem e o usuario e qual o estado da sessao
- `pdp` decide se a acao e permitida
- `pep` faz o enforcement e conecta as duas pontas

## Estado atual

O PDP ja e util para sistemas reais e combina bem com aplicacoes multi-servico, inclusive produtos estilo rede social. Ainda assim, ele continua sendo uma base de plataforma, nao um control plane completo de policy. Versionamento de policy, workflows de aprovacao e invalidacao distribuida mais rica continuam como trabalho futuro.

