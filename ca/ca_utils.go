package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"

	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/putil"
)

const (
	rootCAPrefix          = "Armored Pebble Root CA "
	intermediateCAPrefix  = "Armored Pebble Intermediate CA "
	defaultValidityPeriod = 157766400
	RootCAPUFs            = 10
	IntermediateCAPUFs    = 15
)

type CAImpl struct {
	log              *log.Logger
	db               *db.MemoryStore
	ocspResponderURL string

	chains []*chain

	certValidityPeriod uint64
}

type chain struct {
	root          *issuer
	intermediates []*issuer
}

type issuer struct {
	key      crypto.Signer
	cert     *core.Certificate
	pufs     []*putil.SimPUF
	itype    putil.IssuerType
	resp     []byte
	hptr     []byte
	provChal []byte
	pubProof putil.PubProof
}

func makeSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(fmt.Sprintf("unable to create random serial number: %s", err.Error()))
	}
	return serial
}

func (c *chain) String() string {
	fullchain := append(c.intermediates, c.root)
	n := len(fullchain)

	names := make([]string, n)
	for i := range fullchain {
		names[n-i-1] = fullchain[i].cert.Cert.Subject.CommonName
	}
	return strings.Join(names, " -> ")
}

// Taken from https://github.com/cloudflare/cfssl/blob/b94e044bb51ec8f5a7232c71b1ed05dbe4da96ce/signer/signer.go#L221-L244
func makeSubjectKeyID(key crypto.PublicKey) ([]byte, error) {
	// Marshal the public key as ASN.1
	pubAsDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	// Unmarshal it again so we can extract the key bitstring bytes
	var pubInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pubAsDER, &pubInfo)
	if err != nil {
		return nil, err
	}

	// Hash it according to https://tools.ietf.org/html/rfc5280#section-4.2.1.2 Method #1:
	ski := sha1.Sum(pubInfo.SubjectPublicKey.Bytes)
	return ski[:], nil
}

// makeKey and makeRootCert are adapted from MiniCA:
// https://github.com/jsha/minica/blob/3a621c05b61fa1c24bcb42fbde4b261db504a74f/main.go

// makeKey creates a new 2048 bit RSA private key and a Subject Key Identifier
func makeKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ski, err := makeSubjectKeyID(key.Public())
	if err != nil {
		return nil, nil, err
	}
	return key, ski, nil
}
