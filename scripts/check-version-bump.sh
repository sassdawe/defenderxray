#!/usr/bin/env bash
# CI guard: fails when functional extension files change without a corresponding
# version increment in extension/manifest.json.
#
# Usage (against base branch in a PR):
#   ./scripts/check-version-bump.sh <base-ref>
#
# Usage (against previous commit, e.g. in a push hook):
#   ./scripts/check-version-bump.sh HEAD~1
#
# Exit codes:
#   0 – version bump present, or no functional files changed
#   1 – functional files changed but manifest version was not bumped

set -euo pipefail

BASE="${1:-HEAD~1}"

FUNCTIONAL_PATTERNS=(
    "extension/panel.js"
    "extension/panel.html"
    "extension/panel.css"
    "extension/codegen.js"
    "extension/redaction.js"
    "extension/manifest.json"
)

# 1. Collect changed files
changed_files=$(git diff --name-only "${BASE}" HEAD 2>/dev/null) || {
    echo "error: could not run git diff against '${BASE}'" >&2
    exit 1
}

# 2. Check whether any functional file was changed
functional_changed=false
for pattern in "${FUNCTIONAL_PATTERNS[@]}"; do
    if echo "${changed_files}" | grep -qF "${pattern}"; then
        functional_changed=true
        break
    fi
done

if [[ "${functional_changed}" == "false" ]]; then
    echo "ok: no functional files changed — version bump not required."
    exit 0
fi

# 3. Compare manifest version between base and HEAD
version_head=$(git show HEAD:extension/manifest.json \
    | grep '"version"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
version_base=$(git show "${BASE}:extension/manifest.json" 2>/dev/null \
    | grep '"version"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")

if [[ -z "${version_base}" ]]; then
    echo "ok: manifest.json is new — treating as initial version ${version_head}."
    exit 0
fi

if [[ "${version_head}" == "${version_base}" ]]; then
    echo "error: functional files changed but manifest version was not bumped." >&2
    echo "  base: ${version_base}" >&2
    echo "  head: ${version_head}" >&2
    echo "  Bump the version in extension/manifest.json before merging." >&2
    exit 1
fi

echo "ok: version bumped from ${version_base} to ${version_head}."
exit 0