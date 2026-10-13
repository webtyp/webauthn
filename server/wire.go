package server

import "webtyp.com/model"

type credentialJSON struct {
	ID       string
	RawID    string
	Type     string
	Response responseJSON
}

func (c *credentialJSON) IsNil() bool { return c == nil }
func (c *credentialJSON) DecodeFields(r model.FieldReader) {
	if v, ok := r.String("id"); ok {
		c.ID = v
	}
	if v, ok := r.String("rawId"); ok {
		c.RawID = v
	}
	if v, ok := r.String("type"); ok {
		c.Type = v
	}
	r.Object("response", &c.Response)
}

type responseJSON struct {
	ClientDataJSON     string
	AttestationObject  string
	AuthenticatorData  string
	PublicKey          string
	Signature          string
	UserHandle         string
	PublicKeyAlgorithm int64
}

func (r *responseJSON) IsNil() bool { return r == nil }
func (r *responseJSON) DecodeFields(fr model.FieldReader) {
	if v, ok := fr.String("clientDataJSON"); ok {
		r.ClientDataJSON = v
	}
	if v, ok := fr.String("attestationObject"); ok {
		r.AttestationObject = v
	}
	if v, ok := fr.String("authenticatorData"); ok {
		r.AuthenticatorData = v
	}
	if v, ok := fr.String("publicKey"); ok {
		r.PublicKey = v
	}
	if v, ok := fr.String("signature"); ok {
		r.Signature = v
	}
	if v, ok := fr.String("userHandle"); ok {
		r.UserHandle = v
	}
	if v, ok := fr.Int("publicKeyAlgorithm"); ok {
		r.PublicKeyAlgorithm = v
	}
}

type clientData struct {
	Type      string
	Challenge string
	Origin    string
}

func (c *clientData) IsNil() bool { return c == nil }
func (c *clientData) DecodeFields(r model.FieldReader) {
	if v, ok := r.String("type"); ok {
		c.Type = v
	}
	if v, ok := r.String("challenge"); ok {
		c.Challenge = v
	}
	if v, ok := r.String("origin"); ok {
		c.Origin = v
	}
}

const (
	typeCreate     = "webauthn.create"
	typeGet        = "webauthn.get"
	algES256       = -7
	flagUP         = 0x01
	flagUV         = 0x04
	flagAT         = 0x40
	rpIDHashLen    = 32
	authDataMinLen = 37
)
