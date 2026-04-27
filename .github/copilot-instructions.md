# Defender XRay – Copilot Instructions

## Version bumping

`extension/manifest.json` uses semantic versioning (`MAJOR.MINOR.PATCH`).
**Increment the version whenever a functional change is introduced.**

| Change type | Version segment |
|---|---|
| Breaking change or major new capability | MAJOR |
| New backward-compatible feature or behaviour | MINOR |
| Bug fix, small refinement, or internal improvement | PATCH |

**Do not** change the version for docs-only, comment-only, test-only, or formatting-only edits.

Functional files that require a version bump when changed:
- `extension/panel.js`
- `extension/panel.html`
- `extension/panel.css`
- `extension/codegen.js`
- `extension/redaction.js`
- `extension/manifest.json` (itself, e.g. permissions changes)

## Redaction policy

Sensitive session data (tokens, cookies, auth/session credentials) must never be exposed in UI
details panels or exported JSON. All sanitization goes through `extension/redaction.js`; do not
duplicate or bypass those helpers in `panel.js` or elsewhere.

## Testing

Run `npm test` after any change to `extension/redaction.js`. All redaction regression tests must
pass before considering a change complete.