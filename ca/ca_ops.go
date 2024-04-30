package ca

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	rnd "math/rand"
	"time"

	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/pcert"
	"github.com/letsencrypt/pebble/v2/putil"
	"github.com/letsencrypt/pebble/v2/trclient"
)

func (ca *CAImpl) makeRootCert(
	subjectProof putil.PubProof,
	subject pkix.Name,
	subjectKeyID []byte,
	signer *issuer) (*core.Certificate, putil.LevelOut, error) {

	serial := makeSerial()
	template := &x509.Certificate{
		Subject:      subject,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          subjectKeyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	//fmt.Println("In [makeRootCert] the issuer")
	var parent *x509.Certificate
	var info putil.IssueInfo
	if signer.cert != nil && signer.cert.Cert != nil { // signer is valid ==> non root CAs
		parent = signer.cert.Cert
	} else { // signer is nil ==> root certs
		parent = template
	}

	info, err := ca.makeIssueInfo(signer)
	if err != nil {
		return nil, putil.LevelOut{}, err
	}

	der, aux, err := pcert.CreatePUFCertificate(template, parent, subjectProof, info)
	if err != nil {
		return nil, putil.LevelOut{}, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, putil.LevelOut{}, err
	}

	// fmt.Println("Size output:", len(cert.Signature))
	// fmt.Println("Size output:", len(cert.RawSubjectPublicKeyInfo))
	// fmt.Println("Size output:", len(cert.Extensions), len(cert.Extensions[len(cert.Extensions)-1].Value))

	// Now lets create and upload the PUF entry
	invo_entry, err := trclient.CreatePUFEntry(parent.Subject.CommonName, info, aux.ResponseSig, aux.CompRP, cert.RawTBSCertificate)
	if err != nil {
		return nil, putil.LevelOut{}, err
	}
	// if len(invo_entry) > 0 {
	// }

	err = trclient.AppendEntry(invo_entry)
	if err != nil {
		return nil, putil.LevelOut{}, err
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:   hexSerial,
		Cert: cert,
		DER:  der,
	}
	if signer != nil && signer.cert != nil {
		newCert.IssuerChains = make([][]*core.Certificate, 1)
		newCert.IssuerChains[0] = []*core.Certificate{signer.cert}
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, putil.LevelOut{}, err
	}

	return newCert, aux, nil
}

func makePublicPUFproof(pufs []*putil.SimPUF, provChal []byte) putil.PubProof {
	proof := make([]byte, putil.PUF_LENGTH)
	for i := 0; i < len(pufs); i++ {
		p := pufs[i].GetResponse(provChal)
		for k := 0; k < len(p); k++ {
			proof[k] ^= p[k]
		}
	}
	return proof
}

// depth means which level the issuer is in the CA chain.

func (ca *CAImpl) makeIssueInfo(issuer *issuer) (putil.IssueInfo, error) {
	var info putil.IssueInfo

	ts, err := time.Now().MarshalBinary()
	if err != nil {
		return putil.IssueInfo{}, fmt.Errorf("[Err] error occurred when generating the timestamp")
	}

	info.ITime = ts
	info.IType = issuer.itype
	info.ResponseSig = issuer.resp
	info.HashPointer = issuer.hptr
	info.ProvChall = issuer.provChal
	info.PUFInst = issuer.pufs[rnd.Intn(len(issuer.pufs))]
	info.PubPUFProof = issuer.pubProof

	return info, nil
}

func (ca *CAImpl) GetNumberOfRootCerts() int {
	return len(ca.chains)
}

func (ca *CAImpl) getChain(no int) *chain {
	if 0 <= no && no < len(ca.chains) {
		return ca.chains[no]
	}
	return nil
}

func (ca *CAImpl) GetRootCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.root.cert
}

func (ca *CAImpl) GetRootKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.root.key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}

// GetIntermediateCert returns the first (closest the the leaf) issuer certificate
// in the chain identified by `no`.
func (ca *CAImpl) GetIntermediateCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.intermediates[0].cert
}

func (ca *CAImpl) GetIntermediateKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.intermediates[0].key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}
