# Security Notes and Findings

### P0
- **Admin exposure**: Admin rotas não são registradas quando `PDP_ADMIN_TOKEN` está vazio. Ao definir o token, mantenha o serviço ligado a `127.0.0.1` (compose já mapeia para loopback) ou rede interna e não exponha a porta externamente. Recomendado: mTLS no futuro gateway/mesh.
- **Admin sem token**: Se o token não estiver configurado, `/v1/admin/*` responde 503 ("admin endpoints disabled") para falhar fechado.

### P1
- **Rate limit em admin**: decision/batch usam rate limiter; admin depende de rede restrita + token forte. Recomendação futura: rate limit/mTLS no gateway.
- **ReadHeaderTimeout**: `ReadHeaderTimeout=2s` reduz slowloris.

### P2
- **Input validation**: `DisallowUnknownFields` e limite de 1 MiB em decision/batch/admin. Tenant mismatch sempre nega.
- **Cache safety**: Cache de decisão só guarda RBAC allow; ownership/step-up não são cacheados; chave inclui tenant+user+action+resource.
- **Logging**: Logs não incluem tokens/admin headers; apenas método, path e status.

### Testes de reprodução
- Admin sem token: `curl -X POST http://127.0.0.1:8080/v1/admin/roles -d '{}' -H 'Content-Type: application/json'` -> 401.
- Admin com token: `curl -X POST http://127.0.0.1:8080/v1/admin/roles -H 'X-Admin-Token: <token>' -d '{"name":"r"}'`.
- Admin sem token configurado: `curl -X POST http://127.0.0.1:8080/v1/admin/roles -d '{}' -H 'Content-Type: application/json'` quando `PDP_ADMIN_TOKEN` vazio -> 503.
- Decision tenant mismatch: subject.tenant_id ≠ resource.tenant_id -> allow=false.
- Unknown field: incluir campo extra em `/v1/decision` -> 400.
