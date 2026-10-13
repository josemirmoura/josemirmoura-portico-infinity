#!/usr/bin/env python3
"""Non-mutating overview of Portico approval channel configuration.

This reports configuration only, not whether an HTTPS operator has been
authenticated or whether an MCP App actually rendered in a specific client.
Never source .env or print sensitive values.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


def inspect_configuration(path: Path) -> tuple[str, list[str]]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "operator_fallback", ["Arquivo .env ausente."]
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return "operator_fallback", ["Arquivo .env não é um arquivo regular."]
    if stat.S_IMODE(info.st_mode) & 0o077:
        return "operator_fallback", ["Arquivo .env com permissões excessivas."]

    # Refuse large or malformed files, without evaluating shell expansion.
    if info.st_size > 1024 * 1024:
        return "operator_fallback", ["Arquivo .env excede limite de leitura."]
    try:
        data = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "operator_fallback", ["Não foi possível ler .env."]

    env: dict[str, str] = {}
    for line in data.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#") or "=" not in trimmed:
            continue
        key, value = trimmed.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        # This is a configuration *inspection*, not a shell evaluation.
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        env[key] = value

    required = {
        "PORTICO_OPERATOR_PUBLIC_ORIGIN": "Origem HTTPS do operador ausente.",
        "VPS_AGENT_OPERATOR_PORTAL_URL": "Link HTTPS da Central ausente.",
        "VPS_AGENT_OPERATOR_APPROVAL_TOKEN": "Credencial restrita da Central ausente.",
        "PORTICO_OPERATOR_PASSWORD_SCRYPT": "Senha independente da Central ausente.",
    }
    warnings = [warning for key, warning in required.items() if not env.get(key)]
    if warnings:
        return "operator_fallback", warnings

    origin = env["PORTICO_OPERATOR_PUBLIC_ORIGIN"]
    portal = env["VPS_AGENT_OPERATOR_PORTAL_URL"]
    try:
        u = urlsplit(origin)
        p = urlsplit(portal)
        origin_valid = (
            u.scheme == "https" and bool(u.hostname) and
            u.path in ("", "/") and not u.query and not u.fragment and
            not u.username and not u.password
        )
        portal_valid = (
            p.scheme == "https" and p.netloc == u.netloc and
            p.path == "/operator" and not p.query and not p.fragment and
            not p.username and not p.password
        )
        _ = u.port
        _ = p.port
    except ValueError:
        origin_valid = portal_valid = False
    if not origin_valid or not portal_valid:
        return "operator_fallback", ["Origem e link da Central não correspondem a um HTTPS seguro."]

    secret = env["VPS_AGENT_OPERATOR_APPROVAL_TOKEN"]
    salt_hash = env["PORTICO_OPERATOR_PASSWORD_SCRYPT"].split(":")
    if len(secret) < 32 or len(salt_hash) != 2 or not all(
        re.fullmatch(r"[0-9a-fA-F]+", v or "") for v in salt_hash
    ) or len(salt_hash[0]) != 48 or len(salt_hash[1]) != 64:
        return "operator_fallback", ["Credenciais da Central não atendem ao formato esperado."]

    notes = ["Central HTTPS configurada, mas implantação, login e Broker ainda não verificados."]
    if env.get("VPS_AGENT_MCP_APPS") == "1":
        if not env.get("PORTICO_OPERATOR_FRAME_ANCESTORS"):
            notes.append("MCP Apps ativado sem origens de iframe verificadas: não presumir UI embutida.")
        else:
            notes.append("MCP Apps configurado; renderização e CSP dependem do cliente real.")
    else:
        notes.append("MCP Apps desabilitado por padrão; link HTTPS/SSH é o fallback.")
    return "operator_web_candidate", notes


def main() -> int:
    parser = argparse.ArgumentParser(description="Check operator approval configuration without mutation.")
    parser.add_argument("--env-file", default=".env", type=Path)
    args = parser.parse_args()
    channel, observations = inspect_configuration(args.env_file)
    print("PORTICO_APPROVAL_CONFIG: " + channel)
    for note in observations:
        print("  " + note)
    print("A confirmação de ferramenta do ChatGPT não concede acesso a pastas.")
    print("A decisão exige operador autenticado no Broker. Nenhuma alteração foi feita.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
