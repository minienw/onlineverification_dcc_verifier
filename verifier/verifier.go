package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/common"
	"math/big"
	"os"
)

type Verifier struct {
	publicKeysPath string
}

type VerifiedHCert struct {
	HealthCertificate *common.HealthCertificate
	PublicKey         *AnnotatedEuropeanPk
	ProofIdentifier   []byte
}

func New(publicKeysPath string) *Verifier {
	return &Verifier{
		publicKeysPath: publicKeysPath,
	}
}

func (v *Verifier) VerifyQREncoded(proofPrefixed []byte) (*VerifiedHCert, error) {
	cwt, err := common.UnmarshalQREncoded(proofPrefixed)
	if err != nil {
		return nil, err
	}

	return v.Verify(cwt)
}

func readPubKeys(publicKeysPath string) (PksLookup, error) {
	pksJson, err := os.ReadFile(publicKeysPath)

	if len(pksJson) == 0 || err != nil {
		errors.WrapPrefix(err, "Could not read public keys file.", 0)
		return nil, err
	}

	fmt.Println("Public keys >>>")
	fmt.Println(string(pksJson))
	fmt.Println("<<<Public keys")

	var epks PksLookup
	err = json.Unmarshal(pksJson, &epks)
	if len(epks) == 0 || err != nil {
		errors.WrapPrefix(err, "Could not parse public key content.", 0)
		return nil, err
	}

	return epks, nil
}

func (v *Verifier) Verify(cwt *common.CWT) (*VerifiedHCert, error) {
	// Unmarshal protected header
	var protectedHeader *common.CWTHeader
	err := cbor.Unmarshal(cwt.Protected, &protectedHeader)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not CBOR unmarshal protected header for verification", 0)
	}

	if protectedHeader == nil {
		return nil, errors.Errorf("No protected header is present in CWT")
	}

	// Try to find the KID and public key(s)
	kid, err := findKID(protectedHeader, &cwt.Unprotected)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Couldn't find CWT KID", 0)
	}

	pksLookup, err := readPubKeys(v.publicKeysPath)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could find public keys", 0)
	}

	pks, err := pksLookup.findIssuerPk(kid)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not find key for verification", 0)
	}

	// Calculate the CWT hash
	hash, err := common.SerializeAndHashForSignature(cwt.Protected, cwt.Payload)
	if err != nil {
		return nil, err
	}

	// Try to verify with all public keys; which in practice is one key
	pk, canonicalSignature, err := verifySignature(protectedHeader.Alg, pks, hash, cwt.Signature)
	if err != nil {
		return nil, err
	}

	// Unmarshal verified payload and metadata
	hcert, err := common.ReadCWT(cwt)
	if err != nil {
		return nil, err
	}

	return &VerifiedHCert{
		HealthCertificate: hcert,
		PublicKey:         pk,
		ProofIdentifier:   common.CalculateProofIdentifier(canonicalSignature),
	}, nil
}

func findKID(protectedHeader *common.CWTHeader, unprotectedHeader *common.CWTHeader) (kid []byte, err error) {
	// Determine kid from protected and unprotected header
	if protectedHeader.KID != nil {
		kid = protectedHeader.KID
	} else if unprotectedHeader.KID != nil {
		kid = unprotectedHeader.KID
	} else {
		return nil, errors.Errorf("Could not find key identifier in protected or unprotected header")
	}

	return kid, nil
}

func verifySignature(alg int, pks []*AnnotatedEuropeanPk, hash, signature []byte) (pk *AnnotatedEuropeanPk, canonicalSignature []byte, err error) {
	if len(pks) == 0 {
		return nil, nil, errors.Errorf("No public keys to verify with")
	}

	for _, pk := range pks {
		// Default error
		err = errors.Errorf("Encountered invalid public key type in trusted key store")

		switch pk := pk.LoadedPk.(type) {
		case *ecdsa.PublicKey:
			canonicalSignature, err = verifyECDSASignature(alg, pk, hash, signature)

		case *rsa.PublicKey:
			canonicalSignature, err = verifyRSASignature(alg, pk, hash, signature)
		}

		// Check for successful validation
		if err == nil {
			return pk, canonicalSignature, nil
		}
	}

	// Return last verification error
	return nil, nil, errors.WrapPrefix(err, "Could not verify signature", 0)
}

func verifyECDSASignature(alg int, pk *ecdsa.PublicKey, hash, signature []byte) (canonicalSignature []byte, err error) {
	if alg != common.ALG_ES256 {
		return nil, errors.Errorf("Incorrect algorithm type for ECDSA public key")
	}

	curve := pk.Curve.Params()
	keyByteSize := curve.BitSize / 8
	if len(signature) != keyByteSize*2 {
		return nil, errors.Errorf("Signature has an incorrect length")
	}

	r := new(big.Int).SetBytes(signature[:keyByteSize])
	s := new(big.Int).SetBytes(signature[keyByteSize:])

	ok := ecdsa.Verify(pk, hash, r, s)
	if !ok {
		return nil, errors.Errorf("Signature does not verify against ECDSA public key")
	}

	// Canonicalize s to equal or less than half the curve order
	canonicalSignature = common.CanonicalSignatureBytes(r, s, curve)

	return canonicalSignature, nil
}

func verifyRSASignature(alg int, pk *rsa.PublicKey, hash, signature []byte) (canonicalSignature []byte, err error) {
	if alg != common.ALG_PS256 {
		return nil, errors.Errorf("CWT has incorrect algorithm type for RSA public key")
	}

	err = rsa.VerifyPSS(pk, crypto.SHA256, hash, signature, nil)
	if err != nil {
		return nil, errors.Errorf("CWT signature does not verify against RSA public key")
	}

	return signature, nil
}
