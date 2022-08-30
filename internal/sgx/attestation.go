package sgx

// /*
// #cgo CFLAGS: -g -Wall -I /usr/local/include
// #cgo LDFLAGS: -lp11sgx -L /usr/local/lib

// #include <cryptoki.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <sgx_pce.h>
// #include <QuoteGeneration.h>

// CK_ULONG quote_offset(CK_BYTE_PTR bytes) {
// 	CK_RSA_PUBLIC_KEY_PARAMS* params = (CK_RSA_PUBLIC_KEY_PARAMS*)bytes;
// 	if (params == NULL) {
// 		return 0;
// 	}
// 	CK_ULONG pubKeySize = params->ulModulusLen + params->ulExponentLen;
// 	// check for overflow
// 	if (pubKeySize < params->ulModulusLen || pubKeySize < params->ulExponentLen) {
// 		return 0;
// 	}
//     CK_ULONG offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + pubKeySize;

// 	return offset;
// }

// CK_ULONG params_size(CK_BYTE_PTR bytes) {
//     CK_ULONG offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
// 	return offset;
// }

// CK_ULONG ulModulusLen_offset(CK_BYTE_PTR bytes) {
// 	CK_RSA_PUBLIC_KEY_PARAMS* params = (CK_RSA_PUBLIC_KEY_PARAMS*)bytes;
// 	if (params == NULL) {
// 		return 0;
// 	}
// 	CK_ULONG offset = params->ulModulusLen;
// 	return offset;
// }

// CK_ULONG ulExponentLen_offset(CK_BYTE_PTR bytes) {
// 	CK_RSA_PUBLIC_KEY_PARAMS* params = (CK_RSA_PUBLIC_KEY_PARAMS*)bytes;
// 	if (params == NULL) {
// 		return 0;
// 	}
// 	CK_ULONG offset = params->ulExponentLen;
// 	return offset;
// }

// */
// import "C"

// import (
// 	"context"
// 	"crypto/rsa"
// 	"fmt"
// 	"math"
// 	"math/big"
// 	"strconv"
// 	"unsafe"

// 	"github.com/intel/trusted-certificate-issuer/internal/k8sutil"
// 	"github.com/intel/trusted-certificate-issuer/internal/signer"
// 	"github.com/miekg/pkcs11"
// )

// func (ctx *SgxContext) initiateQuoteAttestation(pending []*signer.Signer) (err error) {
// 	qaPrefix := "sgx.quote.attestation.deliver-"
// 	if len(pending) == 0 {
// 		// No CA signer needs provisioning, just ignore the call.
// 		return nil
// 	}

// 	defer func() {
// 		if err != nil {
// 			for _, s := range pending {
// 				s.SetError(err)
// 			}
// 		}
// 	}()

// 	if ctx.quotePubKey == 0 || ctx.quotePrvKey == 0 || ctx.ctkQuote == nil {
// 		// FIXME: create quote and keypair
// 		return fmt.Errorf("nil SGX quote or quote keypair")
// 	}

// 	name := qaPrefix + strconv.FormatUint(ctx.qaCounter, 10)
// 	ns := ""
// 	ctx.qaCounter++
// 	if len(pending) == 1 {
// 		name, ns = k8sutil.SignerNameToResourceNameAndNamespace(pending[0].Name())
// 	}
// 	pubKey, err := ctx.quotePublicKey()
// 	if err != nil {
// 		return err
// 	}
// 	names := []string{}
// 	for _, ps := range pending {
// 		names = append(names, ps.Name())
// 	}
// 	ctx.log.Info("Initiating quote attestation", "name", name, "forSigners", pending)
// 	err = k8sutil.QuoteAttestationDeliver(
// 		context.TODO(), ctx.k8sClient, name, ns, RequestTypeKeyProvisioning, names, ctx.ctkQuote, pubKey, ctx.cfg.HSMTokenLabel, nil)
// 	if err != nil {
// 		ctx.log.Info("ERROR: Failed to creat QA object")
// 		return err
// 	}

// 	for _, s := range pending {
// 		s.SetPending(name, ns)
// 	}

// 	return nil
// }

// func (ctx *SgxContext) ensureQuote() error {
// 	ctx.ctxLock.Lock()
// 	defer ctx.ctxLock.Unlock()

// 	if ctx.ctkQuote != nil {
// 		return nil
// 	}
// 	ctx.log.Info("Generating quote keypair...")
// 	pub, priv, err := generateP11KeyPair(ctx.p11Ctx, ctx.p11Session)
// 	if err != nil {
// 		return err
// 	}

// 	ctx.log.Info("Generating Quote...")
// 	quote, err := ctx.generateQuote(pub)
// 	if err != nil {
// 		ctx.p11Ctx.DestroyObject(ctx.p11Session, pub)
// 		ctx.p11Ctx.DestroyObject(ctx.p11Session, priv)
// 		return err
// 	}
// 	ctx.quotePubKey = pub
// 	ctx.quotePrvKey = priv
// 	ctx.ctkQuote = quote
// 	return nil
// }

// // quotePublicKey returns the base64 encoded key
// // used for quote generation
// func (ctx *SgxContext) quotePublicKey() (*rsa.PublicKey, error) {
// 	if ctx == nil {
// 		return nil, fmt.Errorf("invalid SGX context")
// 	}
// 	ctx.ctxLock.Lock()
// 	defer ctx.ctxLock.Unlock()

// 	template := []*pkcs11.Attribute{
// 		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
// 		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
// 	}
// 	attrs, err := ctx.p11Ctx.GetAttributeValue(ctx.p11Session, ctx.quotePubKey, template)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var modulus = new(big.Int)
// 	modulus.SetBytes(attrs[0].Value)
// 	var bigExponent = new(big.Int)
// 	bigExponent.SetBytes(attrs[1].Value)
// 	if bigExponent.BitLen() > 32 || bigExponent.Sign() < 1 {
// 		return nil, fmt.Errorf("malformed quote public key")
// 	}
// 	if bigExponent.Uint64() > uint64(math.MaxInt) {
// 		return nil, fmt.Errorf("malformed quote public key: possible data loss in exponent value")
// 	}
// 	exponent := int(bigExponent.Uint64())
// 	return &rsa.PublicKey{
// 		N: modulus,
// 		E: exponent,
// 	}, nil
// }

// func (ctx *SgxContext) generateQuote(pubKey pkcs11.ObjectHandle) ([]byte, error) {
// 	//reader, err := ctx.cryptoCtx.NewRandomReader()
// 	//if err != nil {
// 	//	return nil, fmt.Errorf("failed to initialize random reader: %v", err)
// 	//}

// 	//bytes, err := generateKeyID(reader, C.NONCE_LENGTH)
// 	//if err != nil {
// 	//	return nil, err
// 	//}
// 	// Wrap the key
// 	quoteParams := C.CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS{
// 		qlPolicy: C.SGX_QL_PERSISTENT,
// 	}
// 	for i := 0; i < C.NONCE_LENGTH; i++ {
// 		quoteParams.nonce[i] = C.CK_BYTE(i)
// 	}

// 	params := C.GoBytes(unsafe.Pointer(&quoteParams), C.int(unsafe.Sizeof(quoteParams)))
// 	m := pkcs11.NewMechanism(C.CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY, params)

// 	quotePubKey, err := ctx.p11Ctx.WrapKey(ctx.p11Session, []*pkcs11.Mechanism{m}, pkcs11.ObjectHandle(0), pubKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	offset := uint64(C.quote_offset(*(*C.CK_BYTE_PTR)(unsafe.Pointer(&quotePubKey))))
// 	if offset <= 0 || offset >= uint64(len(quotePubKey)) {
// 		return nil, fmt.Errorf("quote generation failure: invalid quote")
// 	}
// 	return quotePubKey[offset:], nil
// }

// // ParseQuotePublickey reconstruct the rsa public key
// // from received bytes, received bytes structure like this:
// // pubkey_params   |    ulExponentLen   |    ulModulusLen
// // need to slice ulExponentLen and ulModulusLen to
// // reconstruct pubkey according to the size of each item
// func ParseQuotePublickey(pubkey []byte) (*rsa.PublicKey, error) {

// 	paramsSize := uint64(C.params_size(*(*C.CK_BYTE_PTR)(unsafe.Pointer(&pubkey))))
// 	exponentLen := uint64(C.ulExponentLen_offset(*(*C.CK_BYTE_PTR)(unsafe.Pointer(&pubkey))))

// 	var bigExponent = new(big.Int)
// 	bigExponent.SetBytes(pubkey[paramsSize : paramsSize+exponentLen])
// 	if bigExponent.BitLen() > 32 || bigExponent.Sign() < 1 {
// 		return nil, fmt.Errorf("malformed quote public key")
// 	}
// 	if bigExponent.Uint64() > uint64(math.MaxInt) {
// 		return nil, fmt.Errorf("malformed quote public key: possible data loss in exponent value")
// 	}
// 	exponent := int(bigExponent.Uint64())
// 	var modulus = new(big.Int)
// 	modulus.SetBytes(pubkey[paramsSize+exponentLen:])
// 	return &rsa.PublicKey{
// 		N: modulus,
// 		E: exponent,
// 	}, nil
// }
