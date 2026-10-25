#!/bin/bash
# session-start.sh — SessionStart hook for Claude Code on the web.
#
# claude-osint is a Claude *skills package*, not an app: there is no
# package.json/requirements.txt to install. What tests/linters here actually
# need is a short list of CLI tools that aren't guaranteed to be on a fresh
# container:
#   - PyYAML          (frontmatter check + smoke.sh [4], stdlib otherwise)
#   - shellcheck       (CI's `shellcheck` job, .github/workflows/lint.yml)
#   - markdownlint-cli2 (CI's `markdown` job)
#
# See .claude/skills/run-claude-osint/SKILL.md for the full validation
# workflow (`.claude/skills/run-claude-osint/smoke.sh`) that this unblocks.
#
# Only runs on Claude Code on the web — a local checkout already has these
# or the developer manages them themselves.
set -uo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

echo "==> session-start: preparing claude-osint dependencies"

# 1. PyYAML — needed by the SKILL.md frontmatter check (smoke.sh [4] and
#    the CI yaml-frontmatter job). Usually already present; skip if so.
if python3 -c "import yaml" >/dev/null 2>&1; then
  echo "  - pyyaml: already available"
else
  echo "  - pyyaml: installing"
  pip install --quiet pyyaml || echo "  ! pyyaml install failed (frontmatter check will fail)"
fi

# 2. shellcheck — CI's shellcheck job lints ./scripts. Install via apt if
#    missing; non-fatal so a locked-down sandbox doesn't block the session.
if command -v shellcheck >/dev/null 2>&1; then
  echo "  - shellcheck: already available ($(shellcheck --version | awk '/version:/{print $2}'))"
else
  echo "  - shellcheck: installing"
  if apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq shellcheck >/dev/null 2>&1; then
    echo "  - shellcheck: installed"
  else
    echo "  ! shellcheck install failed (apt unavailable or offline) — shellcheck lint will be unavailable"
  fi
fi

# 3. markdownlint-cli2 — CI's markdown job. Installed globally via npm since
#    this repo ships no package.json (nothing to `npm install` locally).
if command -v markdownlint-cli2 >/dev/null 2>&1; then
  echo "  - markdownlint-cli2: already available ($(markdownlint-cli2 --version 2>&1 | head -1))"
else
  echo "  - markdownlint-cli2: installing"
  if npm install -g markdownlint-cli2 >/dev/null 2>&1; then
    echo "  - markdownlint-cli2: installed"
  else
    echo "  ! markdownlint-cli2 install failed (npm unavailable or offline) — markdown lint will be unavailable"
  fi
fi

# 4. Make sure the repo's own driver scripts are executable (git preserves
#    the bit, but this is cheap insurance and keeps the hook idempotent).
chmod +x .claude/skills/run-claude-osint/smoke.sh scripts/sync-skill-content.sh 2>/dev/null || true

echo "==> session-start: done"
