---
PLAN: "feat(server): UnverifiedChallenge — read the challenge of an assertion to find its stored copy (passkey login without a prior session)"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 7371189627170189096
---

> Read AGENTS.md at the repo root before any change.

# PLAN — `server.UnverifiedChallenge`

## Why

`webtyp/auth/passkey` today verifies a passkey only for someone who already has a session: it
stores the challenge under that user's id. `veltylabs/mjosefa-cms` needs a passkey to **be** the
login from the internet (decision D25 of `mjosefa-cms/docs/MVP_DEPLOYMENT_ROADMAP.md`): before
login there is no user id, so the server must find the stored challenge by its own value. The
challenge travels inside the assertion's `clientDataJSON`. This plan exposes it, exactly like the
existing `UnverifiedCredentialID` exposes the `rawId` to load the stored credential. The next
plan (`webtyp/auth`) uses both and then calls `VerifyAssertion`, which checks everything.

## Design gate (api-design)

1. **Prior art.** `go-webauthn/webauthn` `FinishDiscoverableLogin` parses the response first
   (`protocol.ParseCredentialRequestResponseBody`) and looks the session up before verifying;
   SimpleWebAuthn (`verifyAuthenticationResponse`) takes `expectedChallenge` that the app looked up
   from its own store; Yubico `java-webauthn-server` `finishAssertion` requires the request the app
   stored. All read the response, find the stored challenge, then verify.
2. **Names.** `UnverifiedChallenge` pairs with the existing `UnverifiedCredentialID`; the
   `Unverified` prefix says "do not trust this".
3. **Ledger.** Concepts +0 (same pattern as `UnverifiedCredentialID`), ways +0.
4. **Where.** `webauthn/server`: it already decodes `clientDataJSON` (`server.go:211`).
5. **Deletes.** Nothing.

## Stage 1 — `server/server.go`

Below `UnverifiedCredentialID`:

```go
// UnverifiedChallenge returns the challenge bytes inside an Assertion.RawResponse
// (clientDataJSON.challenge) WITHOUT verifying anything. Its only legitimate use is
// finding the stored challenge to pass to VerifyAssertion; never trust it otherwise.
func UnverifiedChallenge(rawResponse string) ([]byte, error)
```

Implementation: decode exactly as `VerifyAssertion` does up to `cdata` (base64 → `credentialJSON`
→ `cred.Response.ClientDataJSON` base64 → `clientData`), then `base64.URLDecode(cdata.Challenge)`.
Any failure, or an empty `ClientDataJSON` or `Challenge`, returns `nil, ErrMalformedResponse`. To
avoid writing the decoding twice, extract `func decodeClientData(rawResponse string) (credentialJSON,
clientData, error)` and make `VerifyAssertion` call it too (its behaviour and errors must not change).

## Stage 2 — tests (in `tests/`, next to the existing `UnverifiedCredentialID` tests)

Build the raw response with the same helpers the assertion tests already use (grep
`UnverifiedCredentialID` in `tests/` and reuse that fixture).

| Test | Input | Expected |
|---|---|---|
| `TestUnverifiedChallenge_ReturnsClientDataChallenge` | a valid assertion signed for challenge `c` | bytes equal `c` |
| `TestUnverifiedChallenge_Malformed` | `"%%%"`, base64 of `{}`, a response with empty `clientDataJSON` | `ErrMalformedResponse` each |
| `TestVerifyAssertion_Unchanged` | run the existing assertion tests | all green, unedited |

## Stage 3 — docs

`README.md` (server section): one line next to `UnverifiedCredentialID`: what it returns, that it
is unverified, and the order "read credential id and challenge → load both → `VerifyAssertion`".

## Delivery check

```
gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission: when the check passes, commit, push and open the PR. Stuck 30
  minutes: open the PR listing what fails.
- `git diff --stat main` lists only: `server/server.go`, the test file(s) in `tests/`,
  `README.md`, this plan.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `server/server.go` | compiles, existing tests green |
| 2 | `tests/…` | new tests pass |
| 3 | `README.md` | line present |
