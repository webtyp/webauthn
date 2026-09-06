//go:build wasm

package webauthn

import (
	"syscall/js"

	"webtyp.com/await"
	"webtyp.com/base64"
)

// GetOptions describes an assertion ceremony.
type GetOptions struct {
	RPID             string
	Challenge        []byte
	AllowCredentials [][]byte // empty means "any discoverable credential"
	UserVerification string
	PRFSalt          []byte // non-nil requests prf evaluation with this salt
}

// Assertion is the result of an assertion ceremony.
type Assertion struct {
	CredentialID []byte
	RawResponse  string // base64url JSON, ready to POST to a verifier
	PRFOutput    []byte // 32 bytes, or nil when prf was not requested or not supported
}

// Get runs navigator.credentials.get. Same goroutine and gesture requirements
// as Create.
func Get(opts GetOptions) (*Assertion, error) {
	if len(opts.Challenge) < 16 {
		return nil, ErrBadChallenge
	}
	if !Available() {
		return nil, ErrUnavailable
	}

	pkOpts := js.Global().Get("Object").New()

	if opts.RPID != "" {
		pkOpts.Set("rpId", opts.RPID)
	}
	pkOpts.Set("challenge", bytesToArrayBuffer(opts.Challenge))

	if len(opts.AllowCredentials) > 0 {
		allowList := js.Global().Get("Array").New()
		for _, credID := range opts.AllowCredentials {
			item := js.Global().Get("Object").New()
			item.Set("type", "public-key")
			item.Set("id", bytesToArrayBuffer(credID))
			allowList.Call("push", item)
		}
		pkOpts.Set("allowCredentials", allowList)
	}

	if opts.UserVerification != "" {
		pkOpts.Set("userVerification", opts.UserVerification)
	}

	if len(opts.PRFSalt) > 0 {
		pkOpts.Set("extensions", buildGetPRFExtension(opts.PRFSalt))
	}

	options := js.Global().Get("Object").New()
	options.Set("publicKey", pkOpts)

	nav := js.Global().Get("navigator")
	creds := nav.Get("credentials")
	promise := creds.Call("get", options)

	res, err := await.Promise(promise)
	if err != nil {
		return nil, mapAwaitError(err)
	}
	if res.IsUndefined() || res.IsNull() {
		return nil, ErrNoCredential
	}

	credID := arrayBufferToBytes(res.Get("rawId"))
	if len(credID) == 0 {
		credID = []byte(res.Get("id").String())
	}

	var prfOutput []byte
	if len(opts.PRFSalt) > 0 {
		if !res.Get("getClientExtensionResults").IsUndefined() && !res.Get("getClientExtensionResults").IsNull() {
			extResults := res.Call("getClientExtensionResults")
			pOut, pErr := parseGetPRFResult(extResults)
			if pErr != nil {
				return nil, pErr
			}
			prfOutput = pOut
		} else {
			return nil, ErrPRFUnsupported
		}
	}

	rawResp := serializeAssertionResponse(res)

	return &Assertion{
		CredentialID: credID,
		RawResponse:  rawResp,
		PRFOutput:    prfOutput,
	}, nil
}

func serializeAssertionResponse(res js.Value) string {
	jsonObj := js.Global().Get("Object").New()
	if !res.Get("id").IsUndefined() {
		jsonObj.Set("id", res.Get("id"))
	}
	if !res.Get("type").IsUndefined() {
		jsonObj.Set("type", res.Get("type"))
	}
	rawIDBytes := arrayBufferToBytes(res.Get("rawId"))
	if len(rawIDBytes) > 0 {
		jsonObj.Set("rawId", base64.URLEncode(rawIDBytes))
	}

	resp := res.Get("response")
	if !resp.IsUndefined() && !resp.IsNull() {
		respObj := js.Global().Get("Object").New()

		cdJSON := arrayBufferToBytes(resp.Get("clientDataJSON"))
		if len(cdJSON) > 0 {
			respObj.Set("clientDataJSON", base64.URLEncode(cdJSON))
		}

		authData := arrayBufferToBytes(resp.Get("authenticatorData"))
		if len(authData) > 0 {
			respObj.Set("authenticatorData", base64.URLEncode(authData))
		}

		sig := arrayBufferToBytes(resp.Get("signature"))
		if len(sig) > 0 {
			respObj.Set("signature", base64.URLEncode(sig))
		}

		uHandle := arrayBufferToBytes(resp.Get("userHandle"))
		if len(uHandle) > 0 {
			respObj.Set("userHandle", base64.URLEncode(uHandle))
		}

		jsonObj.Set("response", respObj)
	}

	if !res.Get("getClientExtensionResults").IsUndefined() && !res.Get("getClientExtensionResults").IsNull() {
		extResults := res.Call("getClientExtensionResults")
		jsonObj.Set("clientExtensionResults", extResults)
	}

	jsonStr := js.Global().Get("JSON").Call("stringify", jsonObj).String()
	return base64.URLEncode([]byte(jsonStr))
}
