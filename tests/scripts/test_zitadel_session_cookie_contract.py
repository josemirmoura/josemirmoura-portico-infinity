"""E2E2 Login V2 cookie signing contract; real Docker OAuth validated by CI."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ZitadelSessionCookieContract(unittest.TestCase):
    def test_patched_images_and_fail_closed_compose(self):
        compose = (ROOT / "compose.integrated-auth.yaml").read_text()
        self.assertIn("ghcr.io/zitadel/zitadel:\${ZITADEL_VERSION:-v4.19.4}", compose)
        self.assertIn("ghcr.io/zitadel/zitadel-login:\${ZITADEL_VERSION:-v4.19.4}", compose)
        self.assertIn("ZITADEL_SESSION_COOKIE_SECRET: \${ZITADEL_SESSION_COOKIE_SECRET:?set ZITADEL_SESSION_COOKIE_SECRET}", compose)

    def test_reuse_generation_and_permissions(self):
        setup = (ROOT / "scripts/setup-integrated-auth.sh").read_text()
        self.assertIn('SESSION_COOKIE_SECRET="$(env_value ZITADEL_SESSION_COOKIE_SECRET || true)"', setup)
        self.assertIn('[ -n "$SESSION_COOKIE_SECRET" ] || SESSION_COOKIE_SECRET="$(openssl rand -hex 32)"', setup)
        self.assertIn('if [ "\${#SESSION_COOKIE_SECRET}" -lt 32 ]; then', setup)
        self.assertIn('upsert_env ZITADEL_SESSION_COOKIE_SECRET "$SESSION_COOKIE_SECRET"', setup)
        self.assertIn('upsert_env ZITADEL_VERSION v4.19.4', setup)
        self.assertIn('umask 077', setup)
        self.assertIn('chmod 600 .env', setup)
        self.assertLess(setup.index("upsert_env ZITADEL_SESSION_COOKIE_SECRET"),
                        setup.index("up -d zitadel-postgres zitadel-api zitadel-login"))

    def test_real_ci_generates_and_checks_secret(self):
        ci = (ROOT / ".github/workflows/integrated-auth.yml").read_text()
        self.assertIn('COOKIE_SECRET="$(openssl rand -hex 32)"', ci)
        self.assertIn('echo "ZITADEL_SESSION_COOKIE_SECRET=$COOKIE_SECRET"', ci)
        self.assertIn('process.env.ZITADEL_SESSION_COOKIE_SECRET', ci)
        self.assertIn('ZITADEL_VERSION=v4.19.4', ci)

    def test_no_vulnerable_default(self):
        for path in ("compose.integrated-auth.yaml", ".env.example",
                     "scripts/setup-integrated-auth.sh", ".github/workflows/integrated-auth.yml"):
            self.assertNotIn("v4.19.1", (ROOT / path).read_text(), path)


if __name__ == "__main__":
    unittest.main()
