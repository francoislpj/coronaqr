// Package coronaqr provides a decoder for EU Digital COVID Certificate (EUDCC)
// QR code data.
//
// See https://github.com/eu-digital-green-certificates for the specs, testdata,
// etc.
package coronaqr

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"

	"github.com/fxamacker/cbor"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/minvws/base45-go/eubase45"
	"go.mozilla.org/cose"

	"crypto/rsa"
	_ "crypto/sha256"
)

// Decoded represents a decoded EU Digital COVID Certificate (EUDCC).
type Decoded struct {
	Cert CovidCert

	// TODO: Include metadata, e.g. certificate timestamp and expiration.
}

type CovidCert struct {
	Version        string          `cbor:"ver"`
	PersonalName   Name            `cbor:"nam"`
	DateOfBirth    string          `cbor:"dob"`
	VaccineRecords []VaccineRecord `cbor:"v"`
}

type Name struct {
	FamilyName    string `cbor:"fn"`
	FamilyNameStd string `cbor:"fnt"`
	GivenName     string `cbor:"gn"`
	GivenNameStd  string `cbor:"gnt"`
}

type VaccineRecord struct {
	Target        string `cbor:"tg"`
	Vaccine       string `cbor:"vp"`
	Product       string `cbor:"mp"`
	Manufacturer  string `cbor:"ma"`
	Doses         int    `cbor:"dn"`
	DoseSeries    int    `cbor:"sd"`
	Date          string `cbor:"dt"`
	Country       string `cbor:"co"`
	Issuer        string `cbor:"is"`
	CertificateID string `cbor:"ci"`
}

type jwkcert struct {
	KeyID string `json:"keyId"`
	Alg   string `json:"alg"`
	Use   string `json:"use"`
	// TODO: x5a
	// TODO: x5aS256
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func jwkFromFile(fn string) (jwk.Set, error) {
	var jwks struct {
		Certs []json.RawMessage /*jwkcert*/ `json:"certs"`
	}
	b, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &jwks); err != nil {
		return nil, err
	}
	log.Printf("loaded %d certs", len(jwks.Certs))

	set := jwk.NewSet()
	for _, cert := range jwks.Certs {
		//patched := strings.Replace(string(cert), "{", `{"kty":"EC",`, 1)
		patched := strings.Replace(string(cert), "{", `{"kty":"RSA",`, 1)
		//log.Printf("cert: %s", patched)
		k, err := jwk.ParseKey([]byte(patched))
		if err != nil {
			return nil, err
		}
		set.Add(k)
	}
	return set, nil
}

// Decode decodes (but does not verify any signatures!) the specified EU Digital
// COVID Certificate (EUDCC) QR code data.
func Decode(qrdata string) (*Decoded, error) {
	if !strings.HasPrefix(qrdata, "HC1:") {
		return nil, errors.New("data does not start with HC1: prefix")
	}

	decoded, err := eubase45.EUBase45Decode([]byte(strings.TrimPrefix(qrdata, "HC1:")))
	if err != nil {
		return nil, err
	}

	zr, err := zlib.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var cborBuf bytes.Buffer
	if _, err := io.Copy(&cborBuf, zr); err != nil {
		return nil, err
	}
	if err := zr.Close(); err != nil {
		return nil, err
	}

	log.Printf("cbor = %x", cborBuf.Bytes())

	type coseHeader struct {
		// Cryptographic algorithm. See COSE Algorithms Registry:
		// https://www.iana.org/assignments/cose/cose.xhtml
		Alg int `cbor:"1,keyasint,omitempty"`
		// Key identifier
		Kid []byte `cbor:"4,keyasint,omitempty"`
		// Full Initialization Vector
		IV []byte `cbor:"5,keyasint,omitempty"`
	}
	type signedCWT struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected coseHeader
		Payload     []byte
		Signature   []byte
	}
	var v signedCWT
	if err := cbor.Unmarshal(cborBuf.Bytes(), &v); err != nil {
		return nil, err
	}

	// COSE algorithm parameter ES256
	// https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-algs/12/

	// TODO: verify signature, add knob to skip the check (decode only)
	log.Printf("protected: %x", v.Protected)
	log.Printf("unprotected: %+v", v.Unprotected)
	log.Printf("len(signature): %d", len(v.Signature))
	log.Printf("signature: %x", v.Signature)

	var p coseHeader
	if err := cbor.Unmarshal(v.Protected, &p); err != nil {
		return nil, err
	}

	log.Printf("p = %+v", p)
	log.Printf("kid = %s", base64.StdEncoding.EncodeToString(p.Kid))
	// use p.Alg and p.Kid

	set, err := jwkFromFile("/tmp/certs.jwk")
	if err != nil {
		return nil, err
	}
	_ = set

	// signer, err := cose.NewSigner(cose.ES256, nil)
	// if err != nil {
	// 	return nil, err
	// }

	sig := cose.NewSignature()
	//sig.Headers.Protected["alg"] = "ES256"
	sig.Headers.Protected["alg"] = "PS256" // or RS256?
	sig.SignatureBytes = v.Signature

	msg := cose.NewSignMessage()
	msg.Payload = v.Payload
	msg.AddSignature(sig)

	//verifier := signer.Verifier()
	k, ok := set.Get(1)
	if !ok {
		return nil, fmt.Errorf("Get(0) = false")
	}
	log.Printf("k = %+v", k)
	jb, err := k.(json.Marshaler).MarshalJSON()
	if err != nil {
		return nil, err
	}
	log.Printf("jb: %q", jb)
	//var pubKey ecdsa.PublicKey
	var pubKey rsa.PublicKey
	if err := k.Raw(&pubKey); err != nil {
		return nil, err
	}
	verifier := &cose.Verifier{
		PublicKey: &pubKey,
		// TODO: supply a ecdsa.PublicKey
		//PublicKey: s.Public(),
		Alg: cose.PS256, // cose.ES256,
	}

	if err := msg.Verify(nil, []cose.Verifier{*verifier}); err != nil {
		return nil, err
	}

	type hcert struct {
		DCC CovidCert `cbor:"1,keyasint"`
	}

	type claims struct {
		Iss   string `cbor:"1,keyasint"`
		Sub   string `cbor:"2,keyasint"`
		Aud   string `cbor:"3,keyasint"`
		Exp   int    `cbor:"4,keyasint"`
		Nbf   int    `cbor:"5,keyasint"`
		Iat   int    `cbor:"6,keyasint"`
		Cti   []byte `cbor:"7,keyasint"`
		HCert hcert  `cbor:"-260,keyasint"`
	}
	var c claims
	if err := cbor.Unmarshal(v.Payload, &c); err != nil {
		return nil, err
	}

	log.Printf("claims: %+v", c)

	return &Decoded{Cert: c.HCert.DCC}, nil
}
