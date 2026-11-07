#!/usr/bin/env python3
"""claude-settings-guard: keep secrets out of committed Claude Code settings.

Claude Code writes every command you approve into .claude/settings.local.json ("permissions.allow").
A command run once with an inline key (STRIPE_SECRET_KEY=sk_live_... node x.js, curl -H "Authorization:
Bearer ...", PGPASSWORD=... psql) lands there verbatim, and the file is per-user: it must never be
committed. Shared .claude/settings.json and .mcp.json are meant to be committed, so they get scanned too.

  claude-settings-guard history <repo> [--log-opts "..."] [--json]   every historical blob (all refs)
  claude-settings-guard pre-push                                       git pre-push hook (stdin = refs)
  claude-settings-guard ci [--range A..B]                              CI: tree + pushed range, exit 1 on fail
  claude-settings-guard install-hook <repo>... | --all-under DIR...    chain-install the pre-push hook
  claude-settings-guard install-ci <checkout>                          write the workflow + this file
  claude-settings-guard hook-status [--fix] [--json] <root>...         is the pre-push guard still in every repo under
                                                                       these roots (healthcare pruned); --fix re-installs
  claude-settings-guard selftest

Findings carry type, JSON location and commit only. Secret values are never printed, logged or stored.
Exit codes: 0 ok, 1 blocked/failed. pre-push fails OPEN on its own errors (prints a warning, allows the push).
Bypass one push on purpose: CLAUDE_SETTINGS_GUARD=off git push ...
Source of truth: crossover-labs/security-check tools/claude-settings-guard.py (2026-11-07, radar-act-1107-1).
VERSION: bump it whenever what CI blocks or warns on changes. Every repo carries a copy (.github/claude-settings-guard.py);
the weekly coverage pass (tools/claude-settings-coverage.py) refreshes copies whose VERSION is older, and only those.
"""
import base64, hashlib, json, math, os, re, subprocess, sys, time

VERSION = "2026-11-07.2"  # .2: aea8567 empty-assignment fix (was shipped as .1), hook-status
PATHSPECS = [":(glob)**/.claude/settings*", ":(glob)**/.mcp.json"]
TARGET_RE = re.compile(r"(^|/)(\.claude/settings[^/]*|\.mcp\.json)$")
LOCAL_RE = re.compile(r"(^|/)\.claude/settings\.local([._~-][^/]*)?$")  # settings.local.json + backups of it
GITIGNORE_LINES = ["# Claude Code per-user settings: approved commands land here verbatim (tokens, passwords)",
                   "**/.claude/settings.local.json", "**/.claude/settings.local.json.*"]
ZERO = "0" * 40
FAKE = re.compile(r"0123456789|abcdefghij|ABCDEFGHIJ|EXAMPLE|example|x{8}|X{8}|\*{4}|REDACTED|your[_-]|YOUR[_-]")

# (type, regex, rotate, confidence). rotate: "yes" = live credential, "no" = public by design, None = graded.
RULES = [
    ("stripe-live-secret-key", r"\b[sr]k_live_[0-9A-Za-z]{10,}", "yes", "high"),
    ("stripe-test-secret-key", r"\b[sr]k_test_[0-9A-Za-z]{10,}", "yes", "high"),
    ("stripe-webhook-secret", r"\bwhsec_[0-9A-Za-z]{20,}", "yes", "high"),
    ("anthropic-key", r"\bsk-ant-[a-z]{2,6}\d{0,3}-[A-Za-z0-9_-]{20,}", "yes", "high"),
    ("openai-key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{40,}\b", "yes", "high"),
    ("xai-key", r"\bxai-[A-Za-z0-9]{40,}", "yes", "high"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}", "yes", "high"),
    ("slack-token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", "yes", "high"),
    ("slack-webhook", r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{12,}", "yes", "high"),
    ("discord-webhook", r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}", "yes", "high"),
    ("telegram-bot-token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", "yes", "high"),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "yes", "high"),
    ("private-key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", "yes", "high"),
    ("supabase-secret-key", r"\bsb_secret_[A-Za-z0-9_-]{20,}", "yes", "high"),
    ("supabase-access-token", r"\bsbp_[a-f0-9]{40}\b", "yes", "high"),
    ("google-refresh-token", r"\b1//0[A-Za-z0-9_-]{30,}", "yes", "high"),  # firebase login:ci tokens
    ("google-oauth-access-token", r"\bya29\.[A-Za-z0-9_-]{20,}", "yes", "medium"),
    ("google-oauth-client-secret", r"\bGOCSPX-[A-Za-z0-9_-]{20,}", "yes", "high"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b", "no", "high"),  # Firebase/Maps browser keys: restrict, no rotation
    ("resend-key", r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}", "yes", "high"),
    ("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}", "yes", "high"),
    ("twilio-api-key", r"\bSK[0-9a-f]{32}\b", "yes", "medium"),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b", "yes", "high"),
    ("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}", "yes", "high"),
    ("shopify-token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", "yes", "high"),
    ("firecrawl-key", r"\bfc-[0-9a-f]{32}\b", "yes", "high"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", None, "high"),
]
# Context rules: the captured group must look like a real value (not $VAR, *, <placeholder>, a path).
CONTEXT = [
    ("credentials-in-url", r"\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@'\"]{1,64}:([^@\s'\"/]{4,})@[A-Za-z0-9.-]", "yes", "high"),
    ("bearer-token", r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})", "yes", "high"),
    ("auth-header", r"(?i)\b(?:x-api-key|api-key|apikey|x-auth-token|x-access-token|authorization)\s*:\s*(?:basic\s+|token\s+)?['\"]?([^\s'\"]{16,})", "yes", "high"),
    ("password-flag", r"(?i)(?:--password[= ]|--passwd[= ]|\bsshpass\s+-p\s*|\bmysql(?:dump|admin)?\b[^\n|;&]{0,80}?\s-p)['\"]?([^\s'\";&|)]{6,})", "yes", "high"),
    ("token-flag", r"(?i)--(?:token|api-key|apikey|auth-token|access-token|secret|client-secret|key)[= ]['\"]?([^\s'\";&|)]{16,})", "yes", "medium"),
    ("basic-auth-flag", r"(?:\bcurl\b[^\n|;&]{0,200}?\s(?:-u|--user)\s+)['\"]?[^\s:'\"]+:([^\s'\";&|)]{4,})", "yes", "high"),
]
# NAME=value assignments: one linear pass (bounded identifier), the name is classified in code. The old
# "[A-Z0-9_]*(?:SECRET|TOKEN...)[A-Z0-9_]*=" form went quadratic on long words full of keywords (55 s on 200 KB).
ASSIGN_RX = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{0,63})\s*=\s*['\"]?([^\s'\";&|)]{6,})")
PASS_NAME = re.compile(r"(?i)pass(word|wd)?$|^pgpassword$|^mysql_pwd$|(^|_)pass(word|wd)?(_|$)")
SECRETISH_NAME = re.compile(r"(?i)secret|token|api_?key|access_?key|private_?key|auth_?key|credentials?")
MAX_CONTEXT_CHARS = 100_000   # context rules skip longer strings (specific key rules still run on everything)
MAX_TEXT_CHARS = 4_000_000    # a Claude settings file is never this big; scan the first 4 MB only
SECRET_NAME = re.compile(r"(?i)(secret|token|passw|pwd|api_?key|apikey|access_?key|private_?key|auth|credential|bearer)")
RULES_C = [(t, re.compile(r), rot, conf) for t, r, rot, conf in RULES]
CONTEXT_C = [(t, re.compile(r), rot, conf) for t, r, rot, conf in CONTEXT]


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def real_value(v):
    v = v.strip("'\"`")
    if len(v) < 4 or FAKE.search(v):
        return False
    if re.match(r"[A-Za-z_][A-Za-z0-9_]*=", v):
        return False  # "KEY= NEXT=..." is an empty assignment followed by the next variable, not a value
    if any(c in v for c in "$*{}<>%") or v.startswith(("~", "/", "./", "../", "@", "-")):
        return False  # $VAR, permission wildcard, template, path, flag
    if re.fullmatch(r"[a-z][a-z._/-]*", v) or re.fullmatch(r"[A-Z][A-Z_]*", v):
        return False  # a word or ENV_NAME, not a value
    if "/" in v and not re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", v):
        return False  # file path / URL fragment
    return entropy(v) >= 2.6 or bool(re.search(r"\d", v) and re.search(r"[A-Za-z]", v))


def jwt_grade(tok):
    try:
        body = tok.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, IndexError):
        return "jwt", "check", "medium", "undecodable"
    if not isinstance(claims, dict):
        return "jwt", "check", "medium", ""
    role = claims.get("role")
    if role == "service_role":
        return "supabase-service-role-jwt", "yes", "high", "bypasses row-level security"
    if role in ("anon", "authenticated"):
        return "supabase-anon-jwt", "no", "high", "public by design"
    if claims.get("scopes") == ["api_read"]:
        return "tmdb-read-token", "no", "high", "read-only, shipped in app bundles"
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        return "jwt", "no", "medium", "expired"
    return "jwt", "yes", "medium", "role=" + str(role or claims.get("iss", "?"))[:40]


def scan_string(s, where):
    out = []
    spans = []
    for t, rx, rot, conf in RULES_C:
        for m in rx.finditer(s):
            val = m.group(0)
            if FAKE.search(val):
                continue
            note = ""
            if t == "jwt":
                t2, rot2, conf2, note = jwt_grade(val)
                out.append({"type": t2, "where": where, "rotate": rot2, "confidence": conf2, "note": note, "_v": val})
            else:
                out.append({"type": t, "where": where, "rotate": rot, "confidence": conf, "note": note, "_v": val})
            spans.append(m.span())
    if len(s) > MAX_CONTEXT_CHARS:
        return out
    for t, rx, rot, conf in CONTEXT_C:
        for m in rx.finditer(s):
            val = m.group(1)
            if any(a <= m.start(1) < b for a, b in spans):
                continue  # already reported by a specific rule
            if real_value(val):
                out.append({"type": t, "where": where, "rotate": rot, "confidence": conf, "note": "", "_v": val})
    for m in ASSIGN_RX.finditer(s):
        name, val = m.group(1), m.group(2)
        if any(a <= m.start(2) < b for a, b in spans):
            continue
        if PASS_NAME.search(name):
            t = "password-assignment"
        elif SECRETISH_NAME.search(name) and len(val.strip("'\"`")) >= 12:
            t = "secret-assignment"
        else:
            continue
        if real_value(val):
            out.append({"type": t, "where": where, "rotate": "yes", "confidence": "medium", "note": "", "_v": val})
    return out


def walk(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            p = f"{path}.{k}" if path else str(k)
            if isinstance(v, str) and SECRET_NAME.search(str(k)) and real_value(v) and len(v) >= 8:
                yield p, v, True
            yield from walk(v, p)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, f"{path}[{i}]")
    elif isinstance(o, str):
        yield path, o, False


def scan_text(text):
    """Findings for one file's content. JSON locations when it parses, else line numbers."""
    found = []
    text = text[:MAX_TEXT_CHARS]
    try:
        data = json.loads(text)
        for where, s, named in walk(data):
            hits = scan_string(s, where)
            if named and not hits:
                hits = [{"type": "named-secret-value", "where": where, "rotate": "yes", "confidence": "medium",
                         "note": "literal value under a secret-looking key", "_v": s}]
            found += hits
    except ValueError:
        for i, line in enumerate(text.splitlines(), 1):
            found += scan_string(line, f"line {i}")
    seen, out = set(), []
    for f in found:
        k = (f["type"], f["where"], f["_v"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def public(f, key=None):
    """Strip the value; keep an HMAC id (per-run key) so the same secret can be matched across files."""
    g = {k: v for k, v in f.items() if not k.startswith("_")}
    if key is not None:
        g["id"] = "s-" + hashlib.blake2b(f["_v"].encode(), key=key, digest_size=5).hexdigest()
    return g


def git(repo, *args, check=False, inp=None):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, input=inp,
                       errors="replace", timeout=900)
    if check and p.returncode:
        raise RuntimeError(f"git {' '.join(args[:3])}: {p.stderr.strip()[:200]}")
    return p.stdout


def blobs_in(repo, revs):
    """[(commit, date, status, path, blob)] for every change to a target path in the given revs, oldest first."""
    out = git(repo, "log", *revs, "--reverse", "-m", "--no-renames", "--format=C %H %cs", "--raw", "--no-abbrev",
              "--", *PATHSPECS)
    rows, commit, date = [], None, None
    for line in out.splitlines():
        if line.startswith("C "):
            _, commit, date = line.split(" ", 2)
        elif line.startswith(":") and "\t" in line:
            meta, path = line.split("\t", 1)
            parts = meta.split()
            if len(parts) >= 5 and TARGET_RE.search(path):
                rows.append((commit, date, parts[4][0], path, parts[3]))
    return rows


def blob_text(repo, blob):
    if blob == ZERO:
        return ""
    return git(repo, "cat-file", "blob", blob)


def tips_tracking(repo, refglobs=("refs/heads", "refs/mini", "refs/vps")):
    """{path: n_branch_tips_where_tracked} for target paths, plus whether HEAD tracks it."""
    head = set(p for p in git(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines() if TARGET_RE.search(p))
    tips = set()
    for line in git(repo, "for-each-ref", "--format=%(objectname) %(refname)", *refglobs).splitlines():
        sha, ref = line.split(" ", 1)
        if ref.startswith("refs/heads/") or "/heads/" in ref:
            tips.add(sha)
    counts = {}
    for sha in tips:
        for p in git(repo, "ls-tree", "-r", "--name-only", sha).splitlines():
            if TARGET_RE.search(p):
                counts[p] = counts.get(p, 0) + 1
    return head, counts


def cmd_history(argv):
    repo = argv[0]
    log_opts = ["--all"]
    if "--log-opts" in argv:
        log_opts = argv[argv.index("--log-opts") + 1].split()
    key = os.urandom(16) if "--ids" in argv else None
    rows = blobs_in(repo, log_opts)
    head, counts = tips_tracking(repo)
    files, cache = {}, {}
    for commit, date, status, path, blob in rows:
        f = files.setdefault(path, {"path": path, "local": bool(LOCAL_RE.search(path)), "first_commit": commit[:10],
                                    "first_date": date, "changes": 0, "blobs": 0, "on_head": path in head,
                                    "branch_tips": counts.get(path, 0), "findings": []})
        f["changes"] += 1
        if blob == ZERO or blob in cache:
            continue
        cache[blob] = True
        f["blobs"] += 1
        for x in scan_text(blob_text(repo, blob)):
            g = public(x, key)
            g["commit"], g["date"] = commit[:10], date
            sig = (g["type"], g["where"], g.get("id"))
            if not any((y["type"], y["where"], y.get("id")) == sig for y in f["findings"]):
                f["findings"].append(g)
    res = {"repo": repo, "files": list(files.values())}
    if "--json" in argv:
        print(json.dumps(res))
    else:
        for f in res["files"]:
            print(f"{f['path']}  first {f['first_commit']} {f['first_date']}  changes {f['changes']}  "
                  f"on HEAD {f['on_head']}  findings {len(f['findings'])}")
            for g in f["findings"]:
                print(f"   {g['type']} at {g['where']} (commit {g['commit']}, rotate {g['rotate']}, {g['confidence']})")
    return 0


def range_problems(repo, revs):
    blocks, warns = [], []
    for commit, date, status, path, blob in blobs_in(repo, revs):
        if LOCAL_RE.search(path) and status == "A":
            blocks.append(f"{commit[:10]} adds {path} (per-user Claude settings must never be committed)")
        elif LOCAL_RE.search(path) and status in "MT":
            warns.append(f"{commit[:10]} changes tracked {path}: untrack it (git rm --cached) and gitignore it")
        if status == "D":
            continue
        for x in scan_text(blob_text(repo, blob)):
            msg = f"{commit[:10]} {path}: {x['type']} at {x['where']}"
            if x["rotate"] == "yes" and x["confidence"] == "high":
                blocks.append(msg + " (treat the key as leaked if it was ever pushed: rotate it)")
            elif x["rotate"] in ("yes", "check"):
                warns.append(msg + " (check: looks like a secret)")
    return blocks, warns


def report(blocks, warns, where):
    for w in warns:
        print(f"claude-settings-guard warning: {w}", file=sys.stderr)
    for b in blocks:
        print(f"claude-settings-guard BLOCKED {where}: {b}", file=sys.stderr)
    if blocks:
        print("Fix: move the value to an env var or secrets file, remove it from the file, rewrite the unpushed "
              "commit (git commit --amend / rebase), and add '**/.claude/settings.local.json' to .gitignore.\n"
              "Deliberate override for one push: CLAUDE_SETTINGS_GUARD=off git push ...", file=sys.stderr)
    return 1 if blocks else 0


def cmd_pre_push(argv):
    if os.environ.get("CLAUDE_SETTINGS_GUARD", "").lower() in ("off", "0", "no"):
        return 0
    try:
        blocks, warns = [], []
        for line in sys.stdin.read().splitlines():
            parts = line.split()
            if len(parts) != 4 or parts[1] == ZERO:
                continue
            loid, roid = parts[1], parts[3]
            if roid != ZERO and git(".", "cat-file", "-t", roid).strip() == "commit":
                revs = [loid, "^" + roid]
            else:
                revs = [loid, "--not", "--remotes"]
            b, w = range_problems(".", revs)
            blocks += b
            warns += w
        return report(sorted(set(blocks)), sorted(set(warns)), "push")
    except Exception as e:  # fail open: a guard bug must never block every push on the machine
        print(f"claude-settings-guard: internal error, push allowed ({type(e).__name__}: {e})", file=sys.stderr)
        return 0


def ignored(repo, path=".claude/settings.local.json"):
    # The repo's own rules only: a machine's global excludes file must not hide a missing .gitignore line.
    return subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, "-c", "core.excludesFile=/dev/null", "check-ignore",
                           "-q", "--no-index", path], capture_output=True).returncode == 0


def cmd_ci(argv):
    repo = "."
    blocks, warns = [], []
    tracked = [p for p in git(repo, "ls-files").splitlines() if TARGET_RE.search(p)]
    for p in tracked:
        if LOCAL_RE.search(p):
            blocks.append(f"{p} is tracked (per-user Claude settings): git rm --cached it")
    for p in ([".claude/settings.local.json"] + sorted({os.path.dirname(os.path.dirname(p)) + "/.claude/settings.local.json"
                                                         for p in tracked if "/.claude/" in p})):
        if not ignored(repo, p.lstrip("/")):
            blocks.append(f"{p.lstrip('/')} is not gitignored: add '**/.claude/settings.local.json' to .gitignore")
    for p in tracked:
        try:
            text = open(os.path.join(repo, p), errors="replace").read()
        except OSError:
            continue
        for x in scan_text(text):
            msg = f"{p}: {x['type']} at {x['where']}"
            if x["rotate"] == "yes" and x["confidence"] == "high":
                blocks.append(msg)
            elif x["rotate"] in ("yes", "check"):
                warns.append(msg)
    if "--range" in argv:
        rng = argv[argv.index("--range") + 1]
        if rng and ".." in rng:
            b, w = range_problems(repo, [rng])
            blocks += b
            warns += w
    print(f"claude-settings-guard {VERSION}: {len(tracked)} Claude settings file(s) tracked, "
          f"{len(blocks)} problem(s), {len(warns)} warning(s)")
    return report(sorted(set(blocks)), sorted(set(warns)), "ci")


HOOK = """#!/bin/sh
# claude-settings-guard pre-push (security-check tools/claude-settings-guard.py). Blocks pushes that add
# .claude/settings.local.json or put a live secret in a Claude settings file. The previous pre-push hook, if
# any, was kept as pre-push.chained and still runs. Fails open if the guard is missing or crashes.
input=$(cat)
G=$(command -v claude-settings-guard 2>/dev/null)
for c in "$HOME/.local/bin/claude-settings-guard" /usr/local/bin/claude-settings-guard; do
  [ -z "$G" ] && [ -x "$c" ] && G="$c"
done
if [ -n "$G" ]; then
  if [ -n "$input" ]; then printf '%s\\n' "$input"; fi | "$G" pre-push "$@"
  rc=$?
  [ "$rc" = 1 ] && exit 1
fi
if [ -x "$(dirname "$0")/pre-push.chained" ]; then
  if [ -n "$input" ]; then printf '%s\\n' "$input"; fi | "$(dirname "$0")/pre-push.chained" "$@" || exit $?
fi
exit 0
"""
HOOK_MARK = "# claude-settings-guard pre-push"


def install_hook(repo):
    g = ["git", "-c", "safe.directory=*", "-C", repo]  # service-user repos on the VPS (root installs for them)
    cd = subprocess.run(g + ["rev-parse", "--path-format=absolute", "--git-common-dir"],
                        capture_output=True, text=True).stdout.strip()
    if not cd:
        return "not a git repo"
    hp = subprocess.run(g + ["config", "core.hooksPath"], capture_output=True, text=True).stdout.strip()
    if hp:
        return f"skipped: core.hooksPath={hp} (CI covers it)"
    hooks = os.path.join(cd, "hooks")
    os.makedirs(hooks, exist_ok=True)
    dst = os.path.join(hooks, "pre-push")
    if os.path.exists(dst) or os.path.islink(dst):
        cur = open(dst, errors="replace").read() if os.path.isfile(dst) else ""
        if HOOK_MARK in cur:
            if cur == HOOK:
                return "ok (current)"
        else:
            chained = os.path.join(hooks, "pre-push.chained")
            if os.path.exists(chained):
                return "skipped: pre-push.chained already exists"
            os.rename(dst, chained)
    tmp = dst + ".tmp-csg"
    with open(tmp, "w") as f:
        f.write(HOOK)
    os.chmod(tmp, 0o755)
    st = os.stat(hooks)
    if os.geteuid() == 0 and st.st_uid != 0:
        os.chown(tmp, st.st_uid, st.st_gid)  # keep the hook owned by the repo's user
    os.replace(tmp, dst)
    return "installed" + (" (chained the existing hook)" if os.path.exists(os.path.join(hooks, "pre-push.chained")) else "")


# Healthcare repos are never walked, read or changed by this tool (the hub may not act on them): the union of the
# security-check, ci-watch and hipaa registry name rules. Callers may add the registry's local paths (skip_paths).
HC_RX = re.compile(r"uptown|wald|cws|capital-?aesthetic|capitalaesthetic|capital-?wound|capitalwound|clinical|hipaa|"
                   r"dr-johnson|mental-health|oak-star-dental|aesthetic|wound", re.I)
WALK_PRUNE = ("node_modules", "DerivedData", "Pods", ".build", "build", ".venv", "venv", "__pycache__")


def walk_repos(roots, skip_paths=()):
    """Git work trees under roots (a repo's nested repos too), healthcare pruned by name before it is entered."""
    skip = {os.path.realpath(os.path.expanduser(p)) for p in skip_paths}
    out = []
    for root in roots:
        root = os.path.expanduser(root)
        if HC_RX.search(root) or not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            dns[:] = sorted(d for d in dns if d not in WALK_PRUNE and not HC_RX.search(d)
                            and os.path.realpath(os.path.join(dp, d)) not in skip)
            if ".git" in dns or ".git" in fns:
                out.append(dp)
                dns[:] = [d for d in dns if d != ".git"]
    return out


def hook_state(repo):
    """-> (state, detail). ok | ok-ci (own core.hooksPath, repo carries the CI workflow) | outdated (our hook, older
    text) | missing (no pre-push) | foreign (another tool's pre-push, no chain yet: install chains it) | not-exec |
    conflict (foreign pre-push AND a pre-push.chained: a tool rewrote our hook after we chained, needs a person) |
    uncovered (own core.hooksPath without our hook and no CI workflow: nothing checks this repo's pushes)."""
    g = ["git", "-c", "safe.directory=*", "-C", repo]
    cd = subprocess.run(g + ["rev-parse", "--path-format=absolute", "--git-common-dir"], capture_output=True, text=True).stdout.strip()
    if not cd:
        return "not-a-repo", ""
    hp = subprocess.run(g + ["config", "core.hooksPath"], capture_output=True, text=True).stdout.strip()
    if hp:
        hd = hp if os.path.isabs(hp) else os.path.join(repo, hp)
        dst = os.path.join(os.path.expanduser(hd), "pre-push")
        if os.path.isfile(dst) and HOOK_MARK in open(dst, errors="replace").read():
            return "ok", f"core.hooksPath={hp}"
        wfp = ".github/workflows/claude-settings-guard.yml"
        if subprocess.run(g + ["ls-files", "--", wfp], capture_output=True, text=True).stdout.strip():
            return "ok-ci", f"core.hooksPath={hp}, CI workflow tracked"
        for ref in ("refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/master"):
            if subprocess.run(g + ["ls-tree", "--name-only", ref, "--", wfp], capture_output=True, text=True).stdout.strip():
                return "ok-ci", f"core.hooksPath={hp}, CI workflow on {ref.split('/', 2)[2]} (this branch predates it)"
        return "uncovered", f"core.hooksPath={hp}, no CI workflow"
    hooks = os.path.join(cd, "hooks")
    dst, chained = os.path.join(hooks, "pre-push"), os.path.join(hooks, "pre-push.chained")
    if not (os.path.exists(dst) or os.path.islink(dst)):
        return "missing", ""
    cur = open(dst, errors="replace").read() if os.path.isfile(dst) else ""
    if HOOK_MARK in cur:
        if not os.access(dst, os.X_OK):
            return "not-exec", "pre-push lost its execute bit (git skips it silently)"
        return ("ok", "") if cur == HOOK else ("outdated", "older guard hook text")
    if os.path.exists(chained):
        return "conflict", "pre-push rewritten by another tool after the guard chained the old one"
    return "foreign", "another pre-push hook, guard not chained"


FIXABLE = ("missing", "foreign", "outdated", "not-exec")
OUR_REMOTE = re.compile(r"github\.com[:/](ajgins|blrbdigital|crossover-labs)/", re.I)


def pushes_somewhere(repo):
    """In scope for the push-time guard: a remote on our GitHub owners, or any SSH remote (client orgs we push to,
    e.g. 3rd-i). A read-only HTTPS clone of a third-party project (firecrawl) or a repo without remotes is not."""
    urls = subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, "remote", "-v"], capture_output=True,
                          text=True).stdout.split()
    return any(OUR_REMOTE.search(u) or u.startswith(("git@", "ssh://")) for u in urls)


def global_excludes():
    p = subprocess.run(["git", "config", "--global", "--get", "core.excludesFile"], capture_output=True, text=True).stdout.strip()
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.expanduser(p) if p else os.path.join(xdg, "git", "ignore")


def drift_report(roots, skip_paths=(), fix=False, bins=("~/.local/bin/claude-settings-guard", "/usr/local/bin/claude-settings-guard")):
    """Everything the push-time guard depends on, on this machine (monaudit-csg-1107). -> (findings, fixed)
    findings: [{key, severity, title, detail, fix}] (state that needs a person or a later run); fixed: [str] repairs made
    now (re-installed hooks, template hook, excludes lines). The hook FAILS OPEN when the binary is missing, so a
    missing or broken binary is high: every repo's pushes go unchecked without any error."""
    F, fixed = [], []

    def add(key, sev, title, detail, how):
        F.append({"key": key, "severity": sev, "title": title, "detail": detail, "fix": how})
    found = [os.path.expanduser(b) for b in bins if os.path.isfile(os.path.expanduser(b)) and os.access(os.path.expanduser(b), os.X_OK)]
    if not found:
        add("bin.missing", "high", "claude-settings-guard binary missing: every pre-push hook here fails open",
            ", ".join(bins), "Reinstall it (Mini: cp tools/claude-settings-guard.py ~/.local/bin/claude-settings-guard; VPS: deploy/install-vps.sh)")
    else:
        b = found[0]
        st = subprocess.run([b, "selftest"], capture_output=True, text=True, timeout=120)
        ver = subprocess.run([b, "version"], capture_output=True, text=True, timeout=60).stdout.strip()
        if st.returncode != 0:
            add("bin.selftest", "high", "claude-settings-guard selftest fails: the pre-push hook would fail open",
                b + ": " + (st.stdout + st.stderr).strip().splitlines()[-1][:200] if (st.stdout + st.stderr).strip() else b,
                "python3 tests/test_claude_settings_guard.py, fix, reinstall")
        elif ver != VERSION:
            add("bin.version", "medium", f"installed claude-settings-guard is {ver or '?'}, source is {VERSION}", b,
                "Reinstall from crossover-labs/security-check (Mini: cp; VPS: deploy/install-vps.sh)")
    tdir = subprocess.run(["git", "config", "--global", "--get", "init.templateDir"], capture_output=True, text=True).stdout.strip()
    if not tdir:
        add("template.unset", "medium", "git init.templateDir is not set: new clones get no pre-push guard", "",
            "git config --global init.templateDir ~/.config/git/template (holds hooks/pre-push)")
    else:
        tp = os.path.join(os.path.expanduser(tdir), "hooks", "pre-push")
        cur = open(tp, errors="replace").read() if os.path.isfile(tp) else ""
        if cur != HOOK and (fix and (not cur or HOOK_MARK in cur)):
            os.makedirs(os.path.dirname(tp), exist_ok=True)
            with open(tp, "w") as f:
                f.write(HOOK)
            os.chmod(tp, 0o755)
            fixed.append(f"template hook {'re-written' if cur else 'restored'}: {tp}")
        elif cur != HOOK:
            add("template.hook", "medium", "the git template's pre-push is not the guard: new clones get no guard",
                tp + (" (another hook there)" if cur else " (missing)"), "claude-settings-guard install-hook on the template, or restore the file")
    ex = global_excludes()
    have = open(ex, errors="replace").read() if os.path.isfile(ex) else ""
    if "**/.claude/settings.local.json" not in have:
        if fix:
            os.makedirs(os.path.dirname(ex), exist_ok=True)
            with open(ex, "a") as f:
                f.write(("" if not have or have.endswith("\n") else "\n") + "".join(l + "\n" for l in GITIGNORE_LINES))
            fixed.append(f"global excludes line restored: {ex}")
        else:
            add("excludes", "medium", "global git excludes no longer ignore .claude/settings.local.json", ex,
                "append '**/.claude/settings.local.json' to it")
    for r in walk_repos(roots, skip_paths):
        if not pushes_somewhere(r):
            continue
        st, detail = hook_state(r)
        if st in ("ok", "ok-ci", "not-a-repo"):
            continue
        if st in FIXABLE:
            if fix and not os.path.exists(os.path.join(r, ".agent.lock")):
                try:
                    res = install_hook(r)
                except OSError as e:
                    res = f"error: {e}"
                if res.startswith(("installed", "ok")):
                    fixed.append(f"pre-push guard re-installed ({st}): {r}")
                    continue
                detail = (detail + "; " if detail else "") + "re-install: " + res
            elif fix:
                detail = (detail + "; " if detail else "") + "fleet run live (.agent.lock): re-installed after it ends"
            add(f"hook.{st}.{r}", "medium", f"pre-push guard {st} in {r}", detail, f"claude-settings-guard install-hook {r}")
        elif st == "conflict":
            add(f"hook.conflict.{r}", "medium", f"pre-push guard overwritten by another tool in {r}", detail,
                "Merge by hand: keep the tool's hook as pre-push.chained and put the guard hook back (claude-settings-guard install-hook)")
        elif st == "uncovered":
            # the repo's .gitignore or this machine's global excludes still keep the file out of 'git add'
            safe = subprocess.run(["git", "-c", "safe.directory=*", "-C", r, "check-ignore", "-q", "--no-index",
                                   ".claude/settings.local.json"], capture_output=True).returncode == 0
            add(f"hook.uncovered.{r}", "low" if safe else "medium",
                f"no push-time Claude settings check in {r}", detail + ("; settings.local.json is still gitignored, so only "
                "'git add -f' or a secret in a shared settings.json gets through" if safe else "; settings.local.json is NOT ignored"),
                "add the guard to the repo's own hooks dir (core.hooksPath) or merge the claude-settings-guard workflow")
    return F, fixed


def cmd_hook_status(argv):
    fix, as_json = "--fix" in argv, "--json" in argv
    roots = [a for a in argv if not a.startswith("--")]
    rows = []
    for r in walk_repos(roots):
        st, detail = hook_state(r)
        if fix and st in FIXABLE:
            if os.path.exists(os.path.join(r, ".agent.lock")):
                detail = (detail + "; " if detail else "") + "not fixed: fleet run live (.agent.lock)"
            else:
                try:
                    detail = (detail + "; " if detail else "") + "fixed: " + install_hook(r)
                except OSError as e:
                    detail = (detail + "; " if detail else "") + f"fix failed: {e}"
        rows.append({"repo": r, "state": st, "detail": detail})
    if as_json:
        print(json.dumps(rows, indent=1))
    else:
        for x in rows:
            print(f"{x['repo']}\t{x['state']}\t{x['detail']}")
        counts = {}
        for x in rows:
            counts[x["state"]] = counts.get(x["state"], 0) + 1
        print("hook-status: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())), file=sys.stderr)
    return 1 if any(x["state"] not in ("ok", "ok-ci", "not-a-repo") and "fixed: installed" not in x["detail"]
                    and "fixed: ok" not in x["detail"] for x in rows) else 0


def cmd_install_hook(argv):
    repos = []
    if argv and argv[0] == "--all-under":
        repos = walk_repos(argv[1:])  # healthcare pruned (HC_RX)
    else:
        repos = argv
    for r in repos:
        if os.path.exists(os.path.join(r, ".agent.lock")):
            print(f"{r}\tskipped: fleet run live (.agent.lock)")
            continue
        try:
            print(f"{r}\t{install_hook(r)}")
        except OSError as e:
            print(f"{r}\terror: {e}")
    return 0


WORKFLOW = """name: claude-settings-guard
# Fails when .claude/settings.local.json is tracked or not gitignored, or a Claude settings file holds a live
# secret. Runs only when Claude settings or .gitignore change. Source: crossover-labs/security-check
# tools/claude-settings-guard.py (copy at .github/claude-settings-guard.py).
on:
  push:
    paths: ['.claude/**', '**/.claude/**', '.mcp.json', '**/.mcp.json', '.gitignore', '**/.gitignore',
            '.github/claude-settings-guard.py', '.github/workflows/claude-settings-guard.yml']
  pull_request:
    paths: ['.claude/**', '**/.claude/**', '.mcp.json', '**/.mcp.json', '.gitignore', '**/.gitignore',
            '.github/claude-settings-guard.py', '.github/workflows/claude-settings-guard.yml']
permissions:
  contents: read
jobs:
  guard:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Claude settings guard
        env:
          BEFORE: ${{ github.event.before }}
          AFTER: ${{ github.sha }}
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          R=""
          if [ -n "$BASE" ]; then R="$BASE..$HEAD_SHA"
          elif [ -n "$BEFORE" ] && [ "$BEFORE" != "0000000000000000000000000000000000000000" ] && git cat-file -e "$BEFORE^{commit}" 2>/dev/null; then R="$BEFORE..$AFTER"; fi
          python3 .github/claude-settings-guard.py ci ${R:+--range "$R"}
"""


def ensure_gitignore(checkout):
    p = os.path.join(checkout, ".gitignore")
    cur = open(p).read() if os.path.exists(p) else ""
    if ignored(checkout) and ignored(checkout, "nested/dir/.claude/settings.local.json"):
        return False  # already covered (e.g. by .claude/ or **/.claude/settings.local.json)
    add = "".join(l + "\n" for l in GITIGNORE_LINES if l not in cur)
    with open(p, "a") as f:
        f.write(("" if not cur or cur.endswith("\n") else "\n") + ("\n" if cur else "") + add)
    return True


def cmd_install_ci(argv):
    co = argv[0]
    os.makedirs(os.path.join(co, ".github", "workflows"), exist_ok=True)
    with open(os.path.join(co, ".github", "workflows", "claude-settings-guard.yml"), "w") as f:
        f.write(WORKFLOW)
    src = open(os.path.abspath(__file__)).read()
    with open(os.path.join(co, ".github", "claude-settings-guard.py"), "w") as f:
        f.write(src)
    changed = ensure_gitignore(co)
    print(f"workflow + guard written; .gitignore {'updated' if changed else 'already ok'}")
    return 0


def cmd_selftest(argv):
    k = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "Qx"
    jwt_sr = "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b'{"role":"service_role","iss":"supabase"}').decode().rstrip("=") + ".c2lnbmF0dXJlc2lnbmF0dXJl"
    jwt_anon = "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b'{"role":"anon","iss":"supabase"}').decode().rstrip("=") + ".c2lnbmF0dXJlc2lnbmF0dXJl"
    pw = "Tr0ub4dor" + "9Qz"
    cases = [
        (json.dumps({"permissions": {"allow": [f"Bash(STRIPE_SECRET_KEY={k} node x.js)"]}}), {"stripe-live-secret-key"}),
        (json.dumps({"permissions": {"allow": [f"Bash(curl -H \"apikey: {jwt_sr}\" https://x.supabase.co)"]}}), {"supabase-service-role-jwt"}),
        (json.dumps({"permissions": {"allow": [f"Bash(curl -H \"apikey: {jwt_anon}\" https://x.supabase.co)"]}}), {"supabase-anon-jwt"}),
        (json.dumps({"permissions": {"allow": [f"Bash(PGPASSWORD={pw} psql -h db)"]}}), {"password-assignment"}),
        (json.dumps({"permissions": {"allow": [f"Bash(sshpass -p '{pw}' ssh root@h)"]}}), {"password-flag"}),
        (json.dumps({"permissions": {"allow": [f"Bash(psql postgres://app:{pw}@db.example.net/x)"]}}), {"credentials-in-url"}),
        (json.dumps({"env": {"OPENAI_API_KEY": "Zq8" + "wLm2Rt7Yp4Kd9Vx1"}}), {"named-secret-value"}),
        (json.dumps({"permissions": {"allow": ["Bash(export STRIPE_SECRET_KEY=*)", "Bash(PGPASSWORD=$PGPASS psql *)",
                                               "Bash(gh auth token)", "Bash(git commit -m *)", "Read(~/.config/token)",
                                               "Bash(curl -H \"Authorization: Bearer $TOKEN\" *)"]}}), set()),
        (json.dumps({"env": {"MAX_TOKENS": "4096", "CLAUDE_CODE_USE_BEDROCK": "0"}}), set()),
        (json.dumps({"permissions": {"allow": ["Bash(STRIPE_SECRET_KEY= STRIPE_WEBHOOK_SECRET= PORT=8080 node server.js)"]}}), set()),
        ("not json " + k, {"stripe-live-secret-key"}),
    ]
    bad = 0
    for text, want in cases:
        got = {f["type"] for f in scan_text(text)}
        if got != want:
            bad += 1
            print(f"FAIL want {sorted(want)} got {sorted(got)} on case {cases.index((text, want))}")
        if any(k in json.dumps(public(f)) for f in scan_text(text)):
            bad += 1
            print("FAIL value leaked into public()")
    print(f"selftest: {len(cases) - bad}/{len(cases)} ok")
    return 1 if bad else 0


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, argv = sys.argv[1], sys.argv[2:]
    return {"history": cmd_history, "pre-push": cmd_pre_push, "ci": cmd_ci, "install-hook": cmd_install_hook,
            "install-ci": cmd_install_ci, "hook-status": cmd_hook_status, "selftest": cmd_selftest, "version": lambda a: print(VERSION) or 0}[cmd](argv)


if __name__ == "__main__":
    sys.exit(main())
