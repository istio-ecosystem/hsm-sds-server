package hsm

import "github.com/miekg/pkcs11"

type HSMConfig struct {
	p11Ctx *pkcs11.Ctx
	// session opened for quote generation
	p11Session pkcs11.SessionHandle
	// private key used for quote generation
	quotePrvKey pkcs11.ObjectHandle
	// private key used for quote generation
	quotePubKey pkcs11.ObjectHandle

	hsmSession pkcs11.SessionInfo
}

type p11Ctx interface {
}
