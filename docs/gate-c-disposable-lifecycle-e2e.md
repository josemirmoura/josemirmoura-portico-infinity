# Gate C: disposable lifecycle E2E (engineering evidence)

Status: **test proposed, not release/production acceptance**. Run on the exact pull-request merge SHA and later on the integrated staging SHA.

## What this workflow exercises

Workflow: `.github/workflows/lifecycle.yml` on a **GitHub-hosted disposable Ubuntu 24.04 runner** with its own Docker daemon, no production VPS connectivity or credentials.

1. Initialize a fresh scoped instance, start the real Gateway and Broker, and verify health and redacted diagnostics.
2. Update via the real `scripts/update.sh` to an ephemeral Git tag and test publication fixture.
3. Inject an invalid Dockerfile as the next ephemeral release, require update failure, previous commit restoration, preserved policy and healthy runtime.
4. Safe-remove the instance, keep operator policy and audit state, and reinstall.
5. Purge the owned running package, verify local policy/state removal and preservation of the delegated host scope.
6. Create an orphaned identity volume *after the successful purge* and verify `--purge` fails closed without deleting that volume.
7. Remove the disposable probe, bootstrap again from the fully purged state, verify a fresh running Broker and valid audit chain, and complete final purge.
8. Publish a minimal no-secret JSON artifact with effective run SHA, run ID, scenario labels and the limits below.

The existing `docker-package-acceptance` also asserts that `--purge` immediately after safe removal is **denied** when the Compose containers are gone but identity volumes remain. It then reinstalls the same checkout to establish Docker project ownership before a permitted purge.

## Security boundary

Never point these workflows at the operator's production host or run them in a copied checkout on the production Docker daemon. The shipped Compose package uses a fixed project identity and privileged host-facing Broker. The new removal guard refuses another checkout's containers and orphaned project volumes/networks/images, but it does not constitute multi-tenant installation isolation.

All fake release tags and test signature verifiers are **synthetic fixtures**. Their successful verification is not proof of an actual signed, immutable GitHub Release. Never label the artifact a signed-production-release test.

## What this cannot approve

- Actual signed RC source/image provenance and upgrade/rollback against a published immutable tag.
- Public DNS/valid HTTPS, real ZITADEL introspection or authenticated ChatGPT MCP call on a designated acceptance host.
- Operator mobile/desktop approval, real-scope deny/grant/revoke, compliance with all normative MCP tests, or independent Gate C review.
- Full destructive uninstall/reinstall of the production VPS.

Gate C remains **BLOCKED** until the independent audit and applicable owner/operator acceptance are completed. Release publication requires the owner's explicit approval. See `docs/operator-acceptance.md` and issue #79.
