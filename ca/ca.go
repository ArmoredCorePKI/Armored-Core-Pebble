package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/letsencrypt/pebble/v2/acme"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/pcert"
	"github.com/letsencrypt/pebble/v2/putil"
	"github.com/letsencrypt/pebble/v2/trclient"
)

func (ca *CAImpl) newRootIssuer(name string) (*issuer, error) {
	// Make a root private key
	rk, subjectKeyID, err := makeKey()
	if err != nil {
		return nil, err
	}

	RootPUFs := putil.InitPUFs(RootCAPUFs)
	// Make a self-signed root certificate
	subject := pkix.Name{
		CommonName: rootCAPrefix + name,
	}
	var rootIssuer issuer
	rootIssuer.key = rk
	rootIssuer.pufs = RootPUFs
	rootIssuer.itype = putil.RootCA
	rootIssuer.provChal = putil.GenRandomBytes(256)
	rootIssuer.pubProof = makePublicPUFproof(rootIssuer.pufs, rootIssuer.provChal)

	rc, level, err := ca.makeRootCert(rootIssuer.pubProof, subject, subjectKeyID, &rootIssuer)
	if err != nil {
		return nil, err
	}
	fmt.Println("Making Root CA Certficates Done.")

	rootIssuer.cert = rc
	rootIssuer.resp = level.ResponseSig
	rootIssuer.hptr = level.HashPointer

	// TODO

	ca.log.Printf("Generated new root issuer %s with serial %s and SKI %x\n", rc.Cert.Subject, rc.ID, subjectKeyID)
	return &rootIssuer, nil
}

func (ca *CAImpl) newIntermediateIssuer(root *issuer, intermediateKey crypto.Signer, subject pkix.Name, subjectKeyID []byte, loc int) (*issuer, error) {
	if root == nil {
		return nil, fmt.Errorf("internal error: root must not be nil")
	}
	IntermediatePUFs := putil.InitPUFs(IntermediateCAPUFs)
	ProveChall := putil.GenRandomBytes(256)
	PublicProof := makePublicPUFproof(IntermediatePUFs, ProveChall)

	// Make an intermediate certificate with the root issuer
	ic, aux, err := ca.makeRootCert(PublicProof, subject, subjectKeyID, root)
	if err != nil {
		return nil, err
	}
	//fmt.Println("cRP: ", hex.EncodeToString(aux.CompRP))
	//ca.log.Printf("Generated new intermediate issuer %s with serial %s and SKI %x\n", ic.Cert.Subject, ic.ID, subjectKeyID)
	issuer_type := putil.IntermediateCA
	if loc == 0 {
		issuer_type = putil.LeafCA
	}
	return &issuer{
		cert:     ic,
		itype:    issuer_type,
		resp:     aux.ResponseSig,
		hptr:     aux.HashPointer,
		pufs:     IntermediatePUFs,
		provChal: ProveChall,
		pubProof: PublicProof,
	}, nil
}

// newChain generates a new issuance chain, including a root certificate and numIntermediates intermediates (at least 1).
// The first intermediate will use intermediateKey, intermediateSubject and subjectKeyId.
// Any intermediates between the first intermediate and the root will have their keys and subjects generated automatically.
func (ca *CAImpl) newChain(intermediateKey crypto.Signer, intermediateSubject pkix.Name, subjectKeyID []byte, numIntermediates int) *chain {
	if numIntermediates <= 0 {
		panic("At least one intermediate must be present in the certificate chain")
	}

	chainID := hex.EncodeToString(makeSerial().Bytes()[:3])

	root, err := ca.newRootIssuer(chainID)
	if err != nil {
		panic(fmt.Sprintf("Error creating new root issuer: %s", err.Error()))
	}
	// fmt.Println("Making Root CA Init Done.")

	// The last N-1 intermediates build a path from the root to the leaf signing certificate.
	// If numIntermediates is only 1, then no intermediates will be generated here.
	prev := root
	intermediates := make([]*issuer, numIntermediates)
	for i := numIntermediates - 1; i > 0; i-- {
		k, ski, err := makeKey()
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %v", err))
		}
		intermediate, err := ca.newIntermediateIssuer(prev, k, pkix.Name{
			CommonName: fmt.Sprintf("%s%s #%d", intermediateCAPrefix, chainID, i),
		}, ski, i)
		if err != nil {
			panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
		}
		intermediates[i] = intermediate
		prev = intermediate
	}

	// The first issuer is the one that signs the domain certificate
	intermediate, err := ca.newIntermediateIssuer(prev, intermediateKey, intermediateSubject, subjectKeyID, 0)
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate issuer: %s", err.Error()))
	}
	intermediates[0] = intermediate

	c := &chain{
		root:          root,
		intermediates: intermediates,
	}
	// ca.log.Printf("Generated issuance chain: %s", c)

	return c
}

func (ca *CAImpl) newCertificate(domains []string, ips []net.IP, key crypto.PublicKey, accountID, notBefore, notAfter string) (*core.Certificate, error) {
	var cn string

	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}

	defaultChain := ca.chains[0].intermediates
	if len(defaultChain) == 0 || defaultChain[0].cert == nil {
		return nil, fmt.Errorf("cannot sign certificate - nil issuer")
	}
	issuer := defaultChain[0]

	subjectKeyID, err := makeSubjectKeyID(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create subject key ID: %s", err.Error())
	}

	certNotBefore := time.Now()
	if notBefore != "" {
		certNotBefore, err = time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return nil, fmt.Errorf("cannot parse Not Before date: %w", err)
		}
	}

	certNotAfter := certNotBefore.Add(time.Duration(ca.certValidityPeriod-1) * time.Second)
	maxNotAfter := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	if certNotAfter.After(maxNotAfter) {
		certNotAfter = maxNotAfter
	}
	if notAfter != "" {
		certNotAfter, err = time.Parse(time.RFC3339, notAfter)
		if err != nil {
			return nil, fmt.Errorf("cannot parse Not After date: %w", err)
		}
	}

	serial := makeSerial()
	template := &x509.Certificate{
		DNSNames:    domains,
		IPAddresses: ips,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    certNotBefore,
		NotAfter:     certNotAfter,

		// we can reserve these non-critical fields.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          subjectKeyID,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ca.ocspResponderURL != "" {
		template.OCSPServer = []string{ca.ocspResponderURL}
	}

	// generate the necessary entries for issuance.
	issue_info, err := ca.makeIssueInfo(issuer)
	if err != nil {
		return nil, err
	}

	//der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert.Cert, key, issuer.key) // Original certificate generation function
	der, aux, err := pcert.CreatePUFCertificate(template, issuer.cert.Cert, key, issue_info) // the core function of Armored Core
	if err != nil {
		return nil, err
	}
	//aux.CompRP
	// fmt.Println("Next Level Data ", aux)

	// go on using the original X509 functions to demonstrate the compatibility
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	// fmt.Println("Size output:", len(cert.Signature))
	// fmt.Println("Size output:", len(cert.RawSubjectPublicKeyInfo))
	// fmt.Println("Size output:", len(cert.Extensions), len(cert.Extensions[len(cert.Extensions)-1].Value))

	// Now lets create and upload the PUF entry
	// Meas_Start()
	invo_entry, err := trclient.CreatePUFEntry(issuer.cert.Cert.Subject.CommonName, issue_info, aux.ResponseSig, aux.CompRP, cert.RawTBSCertificate)
	//Meas_End()
	if err != nil {
		return nil, err
	}
	// if len(invo_entry) > 0 {
	// }

	// fmt.Println(len(invo_entry))

	err = trclient.AppendEntry(invo_entry)
	if err != nil {
		return nil, err
	}

	issuers := make([][]*core.Certificate, len(ca.chains))
	for i := 0; i < len(ca.chains); i++ {
		issuerChain := make([]*core.Certificate, len(ca.chains[i].intermediates))
		for j, cert := range ca.chains[i].intermediates {
			issuerChain[j] = cert.cert
		}
		issuers[i] = issuerChain
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:           hexSerial,
		AccountID:    accountID,
		Cert:         cert,
		DER:          der,
		IssuerChains: issuers,
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func makeSubKey() crypto.PublicKey {
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	return pk.Public()
}

/*
domains [mydomain.test]
ips []
key &{0xa684f0 31027135389409658590674881382566512512440650026342244214837517682435098648914 115504842904376590439271954020947292335026753823844419821664666308294018742889}
key 5de9e437657029c4
notBefore
notAfter
*/

func New(log *log.Logger, db *db.MemoryStore, ocspResponderURL string, alternateRoots int, chainLength int, certificateValidityPeriod uint64) *CAImpl {
	ca := &CAImpl{
		log:                log,
		db:                 db,
		certValidityPeriod: defaultValidityPeriod,
	}

	if ocspResponderURL != "" {
		ca.ocspResponderURL = ocspResponderURL
		ca.log.Printf("Setting OCSP responder URL for issued certificates to %q", ca.ocspResponderURL)
	}

	// test TrillianClient is connected
	chptraw, err := trclient.TC.GetChkpt(trclient.CTX)
	if err != nil {
		panic(fmt.Sprintf("Error connect the trillian logger: %s", err.Error()))
	}
	chpt := trclient.MustOpenCheckpoint(chptraw)
	fmt.Println("Log Checkpoint Size:", chpt.Size)

	intermediateSubject := pkix.Name{
		CommonName: intermediateCAPrefix + hex.EncodeToString(makeSerial().Bytes()[:3]),
	}
	intermediateKey, subjectKeyID, err := makeKey()
	if err != nil {
		panic(fmt.Sprintf("Error creating new intermediate private key: %s", err.Error()))
	}
	ca.chains = make([]*chain, 1+alternateRoots)
	fmt.Println("Start making CA Chains.")

	// testkeys := makeSubKey()
	// domains := []string{"mydomain.test"}
	// ips := []net.IP{}

	fmt.Println("ca.chains", len(ca.chains))
	for i := 0; i < len(ca.chains); i++ {
		ca.chains[i] = ca.newChain(intermediateKey, intermediateSubject, subjectKeyID, chainLength)
	}

	if certificateValidityPeriod != 0 && certificateValidityPeriod < 9223372038 {
		ca.certValidityPeriod = certificateValidityPeriod
	}

	ca.log.Printf("Using certificate validity period of %d seconds", ca.certValidityPeriod)

	//test for domain certificates

	// ca.newCertificate(domains, ips, testkeys, "5de9e437657029c4", "", "")
	//pcert.Meas_End()
	//fmt.Println("Final time: ", ACC_TIME)

	return ca
}

func (ca *CAImpl) CompleteOrder(order *core.Order) {
	// Lock the order for reading
	order.RLock()
	// If the order isn't set as beganProcessing produce an error and immediately unlock
	if !order.BeganProcessing {
		ca.log.Printf("Error: Asked to complete order %s which had false beganProcessing.",
			order.ID)
		order.RUnlock()
		return
	}
	// Unlock the order again
	order.RUnlock()

	// Check the authorizations - this is done by the VA before calling
	// CompleteOrder but we do it again for robustness sake.
	for _, authz := range order.AuthorizationObjects {
		// Lock the authorization for reading
		authz.RLock()
		if authz.Status != acme.StatusValid {
			return
		}
		authz.RUnlock()
	}

	// issue a certificate for the csr
	csr := order.ParsedCSR
	fmt.Println("Calling newCertificate in normal ACME")
	cert, err := ca.newCertificate(csr.DNSNames, csr.IPAddresses, csr.PublicKey, order.AccountID, order.NotBefore, order.NotAfter)
	if err != nil {
		ca.log.Printf("Error: unable to issue order: %s", err.Error())
		return
	}
	ca.log.Printf("Issued certificate serial %s for order %s\n", cert.ID, order.ID)

	// Lock and update the order to store the issued certificate
	order.Lock()
	order.CertificateObject = cert
	order.Unlock()
}
