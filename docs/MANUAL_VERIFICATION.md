# Manual Verification Instructions

WebAuthn browser APIs interact directly with platform authenticators and security keys. The instructions below detail manual verification procedures using Chrome DevTools Virtual Authenticator and a physical device.

---

## 1. Virtual Authenticator Testing (Chrome DevTools)

### Prerequisites
- Google Chrome browser.
- A local HTTP server hosting a WebAssembly application compiled with `webtyp/webauthn`.

### Setup Steps
1. Open Chrome and navigate to your application URL (e.g. `http://localhost:8080`).
2. Open Chrome DevTools (`F12` or `Cmd+Option+I`).
3. Click the three dots menu in DevTools -> **More tools** -> **WebAuthn**.
4. Check **Enable virtual authenticator environment**.
5. Click **Add authenticator**:
   - Protocol: `ctap2`
   - Transport: `internal`
   - Resident keys: `Supported`
   - User verification: `Supported`
   - **Supports PRF: Checked (Enabled)**

### Test Steps & Expected Outcomes

#### Registration (`Create`)
1. Click the Registration button in your WASM app to invoke `webauthn.Create()`.
2. **Expected Outcome:** `webauthn.Create()` resolves successfully without prompting for physical biometrics. `Credential.PRFEnabled` is `true`. `Credential.RawResponse` contains a non-empty base64url JSON string.

#### Assertion with PRF (`Get`)
1. Click the Assertion button in your WASM app to invoke `webauthn.Get()` with `PRFSalt: []byte("fixed_32_byte_test_salt_12345678")`.
2. **Expected Outcome:** `webauthn.Get()` resolves successfully. `Assertion.PRFOutput` contains exactly 32 bytes of deterministic key material.

#### Verification of Salt Determinism
1. Execute `webauthn.Get()` again with the **same** `PRFSalt`.
   - **Expected Outcome:** `Assertion.PRFOutput` matches the exact 32 bytes from the previous assertion.
2. Execute `webauthn.Get()` with a **different** 32-byte `PRFSalt`.
   - **Expected Outcome:** `Assertion.PRFOutput` returns 32 bytes that differ completely from the first salt's output.

---

## 2. Physical Device Testing (Touch ID / Windows Hello / YubiKey)

### Setup Steps
1. Open your test page on a device supporting built-in biometrics or attach a CTAP2 YubiKey.
2. Ensure DevTools Virtual Authenticator is **disabled**.

### Test Steps & Expected Outcomes

1. **Registration:** Trigger `webauthn.Create()`.
   - **Expected Outcome:** System biometric / PIN dialog appears. Upon completing biometric scan, registration resolves.
2. **Assertion:** Trigger `webauthn.Get()`.
   - **Expected Outcome:** System biometric prompt appears. Upon scan, assertion completes and returns 32-byte `PRFOutput` (if PRF is supported by the authenticator) or `ErrPRFUnsupported` if PRF is unsupported on the platform (e.g. YubiKey via iOS Safari).
3. **User Cancellation:** Trigger `webauthn.Create()` or `webauthn.Get()` and click **Cancel** on the OS prompt.
   - **Expected Outcome:** Function returns `webauthn.ErrAborted`.
