# A1 independent-auditor finding: secure OAuth introspection migration

**Finding:** [Gate C independent audit #130, A1](https://github.com/josemirmoura/mcp-vps-agent-gateway/issues/130#issuecomment-6108527514). Severity **P1**. This branch is **NOT deployed**. The Community Gate C release remains blocked until operator-safe migration and second-party verification are complete.

## Corrected source boundary

- `NewIntegratedOIDCVerifier` rejects plaintext `http://` for non-loopback origins; only numeric loopback HTTP is permitted to support disposable `httptest` fixtures. Invalid schemes, URL embedded credentials, fragments and queries are refused at startup.
- The introspection HTTP client uses ordinary Go TLS verification (no `InsecureSkipVerify`); disables environment proxy usage and refuses redirects without following or forwarding Basic credentials or examined bearer tokens. The response must come from the explicitly configured endpoint.
- Default new integrated-auth bootstrap now configures `https://${VPS_AGENT_DOMAIN}/oauth/v2/introspect` via the existing Traefik trusted public TLS listener, not direct Docker h2c `http://zitadel-auth-internal:8080`.
- Independent A1 307/302 redirects and self-signed TLS invalidity have fail-closed regression tests.

## Deployment migration and operator acceptance STILL REQUIRED

**Do not deploy this branch as-is to an installation whose `.env` still contains the legacy internal HTTP introspection URL.** The new Gateway deliberately rejects that config at startup, preventing silent insecure operation. Existing updates `scripts/update.sh` restore saved `.env` and do not automatically rewrite credentials or configuration, correctly refusing unsafe rollbacks.

A safe separate migration gate must be designed, implemented, and accepted **before any release**:

1. On a disposable isolated Community install, prove the Gateway Docker container can resolve and securely reach `https://${VPS_AGENT_DOMAIN}/oauth/v2/introspect` with valid certificate, through existing Traefik, without DNS/hairpin, redirect or proxy failure. Host curl alone is not sufficient.
2. Preflight with **no credentials in logs** and no service stop; test a deliberately invalid token against the configured endpoint and confirm a valid HTTPS response of `active:false`. This must be done from the Gateway's actual network context.
3. Snapshot and safely migrate an existing install's private `.env` endpoint to HTTPS (preserving file permissions, access, other environment values, broker state and ZITADEL DB). Do not log tokens or secrets. Verify canary authorization with valid/invalid bearer, and fail closed/rollback configuration on unexpected results.
4. Test isolated clean install and upgrade from the last released Community using the actual `scripts/update.sh` implementation **from that released revision**, including missing DNS, inaccessible public edge from container, cert mismatch, redirection, and old `.env` behavior. Block releases until this is green.
5. Independently re-audit A1 at exact new staging SHA and sign off operator migration. Do not change VPS, DNS, main, production, images, tags, or published releases before explicit owner approval.

**Current evidence is source/test-layer only.** A CI green status does not prove this migration, TLS routing or live ChatGPT acceptance; Gate C remains BLOCKED. This HTTPS setting may need replacement with a more robust verified in-network TLS endpoint if public-edge hairpin access fails on representative deployments.
