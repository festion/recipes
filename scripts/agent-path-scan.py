"""Agent-write-path secret scan (ops #3995). HIGH-PRECISION rules only, ENFORCING.

Agent working notes (.serena/, .claude/learnings*, .claude/**/memory/, Claude
memory files, MEMORY.md) are committed with no review. This scan covers ONLY
those globs and fails on shapes that are not ambiguous:

  vendor-token      ghp_/gho_/github_pat_, sk-ant-, xox[abprs]-, AKIA/ASIA, AIza,
                    glpat-, JWT (eyJ..<dot>eyJ..<dot>)
  private-key       PEM "-----BEGIN ... PRIVATE KEY-----" header
  kdf-*             $argon2.. / $2b$.. / pbkdf2_sha256$.. / crypt $6$.. / scrypt / {SSHA}
  url-userinfo      scheme://user:pass@ (placeholders and $VARs excluded)
  public-serena     a PUBLIC repo must not track .serena/ at all

There is deliberately NO entropy or generic-assignment arm: those heuristics
were tuned against false positives until whole secret classes (all-lowercase
passwords, UUID secrets, Bearer tokens) scored 0%. Exact detection of secrets
we HOLD belongs to the digest watcher (note-holders vs Infisical digests).

OUTPUT: file:line, rule id, matched length. Never the value or a digest of it.
Under GITHUB_ACTIONS an ::error annotation is also emitted (names escaped).

Usage
  agent-path-scan.py [--root DIR] PATH...     scan these paths (globs applied)
  agent-path-scan.py [--root DIR] --base SHA  files changed since SHA (git diff)
  agent-path-scan.py [--root DIR] --all       every tracked file
  --public / --private / env REPO_PRIVATE=true   visibility for public-serena;
      anything but "true" is treated as PUBLIC (fail closed).

Exit 0 clean (including "no agent-path files changed"); 1 findings OR any
in-scope file that could not be scanned (missing, unreadable, symlink, NUL byte,
over MAX_BYTES) - reported with a count and reason; 2 usage/git error.
A diff that cannot be computed falls back to scanning every tracked file.
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import PurePosixPath

AGENT_GLOBS = (
    ".serena/**", "**/.serena/**",
    ".claude/learnings*", ".claude/learnings*/**",
    ".claude/**/learnings*", ".claude/**/learnings*/**",
    ".claude/**/memory/**", ".claude/memory/**",
    "**/MEMORY.md", "**/MEMORY-*.md", "MEMORY.md", "MEMORY-*.md",
)
MAX_BYTES = 2_000_000


def _glob_re(glob: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)   # case-insensitive paths


_GLOB_RES = [_glob_re(g) for g in AGENT_GLOBS]


def in_agent_path(rel: str) -> bool:
    rel = PurePosixPath(rel.replace("\\", "/")).as_posix()
    while rel.startswith("./"):
        rel = rel[2:]
    return any(r.match(rel) for r in _GLOB_RES)


RULES = (
    # FLOOR: values shorter than this rule's minimum length are admitted (not flagged) by this
    #   rule. Short secrets (PINs, 8-char WiFi PSKs, 16-char app passwords) are covered by the
    #   nightly note-holders digest watcher (homelab-iac secret-holder-watch), not here.
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-project-key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{32,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}")),
    # FLOOR: shorter values are admitted by this rule; the digest watcher covers them (ops #3995).
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    # FLOOR: values shorter than this rule's minimum length are admitted (not flagged) by this
    #   rule. Short secrets (PINs, 8-char WiFi PSKs, 16-char app passwords) are covered by the
    #   nightly note-holders digest watcher (homelab-iac secret-holder-watch), not here.
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[A-Za-z0-9_\-]{35}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("openai-legacy", re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    # FLOOR: values shorter than this rule's minimum length are admitted (not flagged) by this
    #   rule. Short secrets (PINs, 8-char WiFi PSKs, 16-char app passwords) are covered by the
    #   nightly note-holders digest watcher (homelab-iac secret-holder-watch), not here.
    ("slack-app", re.compile(r"\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{32,}\b")),
    ("kdf-argon2", re.compile(r"\$argon2(?:id|i|d)\$(?:v=\d+\$)?m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}")),
    ("kdf-bcrypt", re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{20,}")),
    # FLOOR: shorter values are admitted by this rule; the digest watcher covers them (ops #3995).
    ("kdf-pbkdf2", re.compile(r"\bpbkdf2[_\-]sha(?:1|256|512)\$[^\s]{8,}|\$pbkdf2-sha(?:1|256|512)\$[^\s]{8,}")),
    # FLOOR: shorter values are admitted by this rule; the digest watcher covers them (ops #3995).
    ("kdf-crypt", re.compile(r"\$(?:1|5|6|y|7)\$[./A-Za-z0-9,=\-]{0,40}\$[./A-Za-z0-9]{16,}")),
    # FLOOR: values shorter than this rule's minimum length are admitted (not flagged) by this
    #   rule. Short secrets (PINs, 8-char WiFi PSKs, 16-char app passwords) are covered by the
    #   nightly note-holders digest watcher (homelab-iac secret-holder-watch), not here.
    ("kdf-scrypt", re.compile(r"\$scrypt\$[^\s]{8,}|\bscrypt\$[^\s]{16,}")),
    ("kdf-ldap", re.compile(r"\{(?:SSHA|SSHA512|SHA512|PBKDF2[A-Z0-9\-]*|ARGON2)\}[A-Za-z0-9+/=$]{16,}")),
)
# scheme://user:pw@ (any case), and bare user:pw@host as in sshpass/rsync/scp
# lines (the host after @ must look like a hostname or IP, so prose "a:b@c"
# does not match). The password may contain '/'.
_USERINFO = re.compile(
    # FLOOR: values shorter than this rule's minimum length are admitted (not flagged) by this
    #   rule. Short secrets (PINs, 8-char WiFi PSKs, 16-char app passwords) are covered by the
    #   nightly note-holders digest watcher (homelab-iac secret-holder-watch), not here.
    r"(?i)(?:\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:(?P<pw>[^\s@]{1,})@(?P<host>[^\s/:@]*)"
    r"|(?<![\w/:@])[a-z_][\w.\-]*:(?P<pw2>[^\s@:/]{6,})@(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9\-]+(?:\.[a-z0-9\-]+)*))")
# Only unmistakable placeholders. Real default credentials (admin, root, test)
# are NOT excused: on an internal host they are working logins.
_PW_PLACEHOLDER = re.compile(
    # FLOOR: values shorter than this rule's minimum length are admitted (not flagged) by this
    #   rule. Short secrets (PINs, 8-char WiFi PSKs, 16-char app passwords) are covered by the
    #   nightly note-holders digest watcher (homelab-iac secret-holder-watch), not here.
    r"^(?:(?i:password|pass|x+|redacted)|[A-Z][A-Z_]{2,}|\*+|<[^>]*>|\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|\{\{.*\}\}|\.+|\u2026)$")
# Test passwords are excused ONLY on loopback URLs (a local dev/test DSN).
_LOOPBACK_TEST_PW = re.compile(r"(?i)^(?:test|dev|demo|example|local|temp|postgres)$")
_LOOPBACK_HOST = re.compile(r"(?i)^(?:localhost|127\.0\.0\.1|\[::1\])$")
# The bare user:pw@host form counts only on a line that runs a transfer/ssh tool.
_BARE_CTX = re.compile(r"(?i)\b(?:ssh|sshpass|rsync|scp|sftp|ftp|lftp)\b")


def scan_text(text: str):
    """Yield (lineno, rule, length). Never yields a value."""
    for ln, line in enumerate(text.splitlines(), 1):
        for rid, rx in RULES:
            for m in rx.finditer(line):
                yield ln, rid, len(m.group(0))
        for m in _USERINFO.finditer(line):
            pw = m.group("pw") if m.group("pw") is not None else m.group("pw2")
            if m.group("pw") is None and not _BARE_CTX.search(line):
                continue
            if (m.group("pw") is not None and _LOOPBACK_HOST.match(m.group("host") or "")
                    and _LOOPBACK_TEST_PW.match(pw)):
                continue
            if not _PW_PLACEHOLDER.match(pw):
                yield ln, "url-userinfo", len(pw)


def _esc_prop(v) -> str:
    """GitHub workflow-command escaping for a property (file name)."""
    return (str(v).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            .replace(":", "%3A").replace(",", "%2C"))


def _esc_data(v) -> str:
    return str(v).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _show(s: str) -> str:
    """A file name on a terminal/log line: control characters made visible."""
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group()):02x}", s)


class GitError(RuntimeError):
    pass


def _git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, check=False)


def tracked(root):
    r = _git(root, "ls-files", "-z")
    if r.returncode != 0:
        raise GitError("git ls-files failed")
    return [p for p in r.stdout.split("\0") if p]


def changed(root, base):
    zeros = not base or set(base) <= {"0"}
    if not zeros:
        r = _git(root, "diff", "--name-only", "-z", "--diff-filter=ACMR", f"{base}...HEAD")
        if r.returncode != 0:
            r = _git(root, "diff", "--name-only", "-z", "--diff-filter=ACMR", base, "HEAD")
        if r.returncode == 0:
            return [p for p in r.stdout.split("\0") if p], False
    return tracked(root), True


def is_public(flag):
    if flag is not None:
        return flag
    return os.environ.get("REPO_PRIVATE", "").strip().lower() != "true"


def read_file(full):
    """(data, None) or (None, reason)."""
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable-or-symlink"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not-a-regular-file"
        if st.st_size > MAX_BYTES:
            return None, "too-large"
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_BYTES + 1)
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)
    if len(data) > MAX_BYTES:
        return None, "too-large"
    if b"\0" in data:
        return None, "binary-nul-byte"
    return data, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="agent-write-path secret scan (ops #3995)")
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--root", default=".")
    ap.add_argument("--base")
    ap.add_argument("--all", action="store_true")
    vis = ap.add_mutually_exclusive_group()
    vis.add_argument("--public", dest="public", action="store_true", default=None)
    vis.add_argument("--private", dest="public", action="store_false")
    a = ap.parse_args(argv)
    root = os.path.abspath(a.root)
    if not (a.paths or a.base is not None or a.all):
        print("usage: give PATH..., --base SHA or --all", file=sys.stderr)
        return 2
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    findings = 0
    try:
        if a.all:
            cands = tracked(root)
        elif a.base is not None:
            cands, fell_back = changed(root, a.base)
            if fell_back:
                print("note: diff unavailable, scanned all tracked files")
        else:
            cands = [os.path.relpath(os.path.abspath(os.path.join(root, p)), root)
                     for p in a.paths]
        public = is_public(a.public)
        if public:
            for p in tracked(root):
                if p.lower() == ".serena" or p.lower().startswith(".serena/") \
                        or "/.serena/" in p.lower():
                    print(f"{_show(p)}:1 public-serena")
                    if gha:
                        print(f"::error file={_esc_prop(p)},line=1::public-serena")
                    findings += 1
    except GitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    scanned, problems = 0, []
    for rel in sorted(set(cands)):
        if not in_agent_path(rel):
            continue
        data, why = read_file(os.path.join(root, rel))
        if why:
            problems.append((rel, why))
            print(f"{_show(rel)}: NOT SCANNED ({why})")
            if gha:
                print(f"::error file={_esc_prop(rel)}::not scanned ({why})")
            continue
        scanned += 1
        seen = set()
        for ln, rid, n in scan_text(data.decode("utf-8", "replace")):
            if (ln, rid) in seen:
                continue
            seen.add((ln, rid))
            print(f"{_show(rel)}:{ln} {rid} len={n}")
            if gha:
                print(f"::error file={_esc_prop(rel)},line={ln}::{_esc_data(rid)} len={n}")
            findings += 1
    if scanned == 0 and not problems:
        print("no agent-path files changed")
    print(f"agent-path-scan: scanned={scanned} findings={findings} "
          f"not_scanned={len(problems)} public={public}")
    return 1 if (findings or problems) else 0


if __name__ == "__main__":
    sys.exit(main())
