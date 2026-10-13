#!/usr/bin/env python3
"""Fail-closed, crash-recoverable ZITADEL operator creation journal.

The journal contains only a planned ID and public account metadata, never a
password/PAT or response credentials. It MUST be persisted before POST.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import uuid


MARKER = "\n__PORTICO_HTTP_STATUS__"


def die(message: str) -> None:
    raise SystemExit("BLOCKED: operator reconciliation: " + message)


def guarded_parent(path: Path) -> None:
    directory = path.parent
    try:
        mode = directory.lstat().st_mode
    except FileNotFoundError:
        directory.mkdir(mode=0o700, parents=False)
        mode = directory.lstat().st_mode
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        die("journal parent is not an ordinary directory")
    if directory.stat().st_uid != os.geteuid():
        die("journal directory has unexpected owner")
    if mode & 0o077:
        die("journal directory permissions must be private (0700)")


def load_journal(path: Path) -> dict | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    except OSError:
        die("cannot securely open journal")
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            die("journal must be a private 0600 regular file owned by this operator")
        if info.st_size > 4096:
            die("journal exceeds allowed size")
        try:
            result = json.load(handle)
        except (UnicodeError, ValueError):
            die("journal is malformed")
    if not isinstance(result, dict) or set(result) != {"version", "id", "domain", "username", "email"}:
        die("journal schema mismatch")
    if result["version"] != 1 or not isinstance(result["id"], str):
        die("journal version or ID invalid")
    try:
        uuid.UUID(result["id"])
    except ValueError:
        die("journal user ID invalid")
    for field in ("domain", "username", "email"):
        if not isinstance(result[field], str) or not result[field]:
            die("journal identity metadata invalid")
    return result


def prepare(path: Path, domain: str, username: str, email: str) -> None:
    guarded_parent(path)
    current = load_journal(path)
    if current:
        if (current["domain"], current["username"], current["email"].casefold()) != (
            domain, username, email.casefold()
        ):
            die("pending operator differs from requested account; do not create another user")
        print(current["id"])
        return
    planned = {
        "version": 1,
        "id": str(uuid.uuid4()),
        "domain": domain,
        "username": username,
        "email": email,
    }
    fd, temp = tempfile.mkstemp(prefix=".operator-journal-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(planned, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Exclusive no-replace behavior. A second writer must not silently
        # overwrite a concurrent journal (the installer is normally serial).
        if path.exists() or path.is_symlink():
            die("journal appeared concurrently; retry without making POST")
        os.link(temp, path, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.unlink(temp)
    print(planned["id"])


def probe(path: Path, user_id: str, username: str, email: str) -> None:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        die("cannot read private identity probe")
    if len(raw) > 1024 * 1024 or raw.count(MARKER) != 1:
        die("unexpected HTTP status framing")
    body, raw_status = raw.rsplit(MARKER, 1)
    code = raw_status.strip()
    if code not in ("200", "404"):
        die("ZITADEL identity lookup returned unexpected HTTP status " + repr(code))
    try:
        response = json.loads(body)
    except (TypeError, ValueError):
        die("ZITADEL identity lookup did not return JSON")
    if not isinstance(response, dict):
        die("ZITADEL identity lookup schema invalid")
    if code == "404":
        error_code = response.get("code")
        if error_code not in (5, "5", "NOT_FOUND"):
            die("404 is not a verified ZITADEL not-found response")
        print("ABSENT")
        return

    user = response.get("user")
    if not isinstance(user, dict):
        die("successful lookup has no user")
    human = user.get("human")
    if not isinstance(human, dict):
        die("lookup found a non-human identity")
    user_email = human.get("email")
    if not isinstance(user_email, dict):
        die("lookup has no validated email structure")
    actual_id = user.get("userId") or human.get("userId")
    actual_name = user.get("username") or human.get("username")
    actual_email = user_email.get("email")
    if (
        actual_id != user_id or actual_name != username or
        not isinstance(actual_email, str) or actual_email.casefold() != email.casefold()
    ):
        die("remote ID, username or email differs from pending journal")
    print("FOUND")


def finalize(journal: Path, marker: Path, user_id: str) -> None:
    guarded_parent(journal)
    data = load_journal(journal)
    if data is None or data["id"] != user_id:
        die("pending journal does not match committed subject")
    if marker.is_symlink():
        die("identity marker must not be a symlink")
    try:
        final = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        die("cannot verify committed identity marker")
    if (final.get("subject"), final.get("domain"), final.get("username"),
        str(final.get("email", "")).casefold()) != (
            user_id, data["domain"], data["username"], data["email"].casefold()
        ):
        die("identity marker does not match the pending account")
    journal.unlink()
    directory_fd = os.open(journal.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "probe", "finalize"):
        item = subs.add_parser(action)
        if action == "prepare":
            item.add_argument("journal", type=Path)
            item.add_argument("domain")
            item.add_argument("username")
            item.add_argument("email")
        if action == "probe":
            item.add_argument("response", type=Path)
            item.add_argument("id")
            item.add_argument("username")
            item.add_argument("email")
        if action == "finalize":
            item.add_argument("journal", type=Path)
            item.add_argument("marker", type=Path)
            item.add_argument("id")
    opts = parser.parse_args()
    if opts.action == "prepare":
        prepare(opts.journal, opts.domain, opts.username, opts.email)
    elif opts.action == "probe":
        probe(opts.response, opts.id, opts.username, opts.email)
    else:
        finalize(opts.journal, opts.marker, opts.id)


if __name__ == "__main__":
    main()
