package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/letsencrypt/pebble/v2/putil"
	"github.com/letsencrypt/pebble/v2/trclient"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/proto"
)

func WholeProtocol() {

	// whole_time := 0

	/*------------------------- Round 1 -------------------------*/

	// get certs, entry, and generate nonce
	raw_cert := CERT_CHAIN[CHAIN_LENGTH-1]
	raw_entry_hex := ENTRY_CHAIN[CHAIN_LENGTH-1]
	n1 := putil.GenRandomBytes(NONCE_LENGTH)

	// recalculate hc

	start_1 := time.Now()
	decoded_cert, _ := pem.Decode([]byte(raw_cert))

	real_cert, err := x509.ParseCertificate(decoded_cert.Bytes)
	if err != nil {
		fmt.Println("error when decode certificates")
	}
	raw_entry, err := hex.DecodeString(raw_entry_hex)
	if err != nil {
		fmt.Println("error when decode hex entries")
	}
	decoded_entry := &trclient.PUFEntry{}
	if err := proto.Unmarshal(raw_entry, decoded_entry); err != nil {
		fmt.Println("error when decode entries")
	}

	h := sha256.New()
	h.Write(real_cert.RawTBSCertificate)
	h.Write(decoded_entry.Ts)
	h.Write([]byte(real_cert.Issuer.CommonName))
	hc := h.Sum(nil)

	h = sha256.New()
	h.Write(hc)
	h.Write(n1)
	temph := h.Sum(nil)
	rl := putil.GenRandomBytes(32)

	/*------------------------- Round 2 -------------------------*/

	// generate m1, n2, and sign
	m1 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		m1[i] = temph[i] ^ rl[i]
	}
	n2 := putil.GenRandomBytes(NONCE_LENGTH)

	signer, err := note.NewSigner(testAttPrivateKey)
	if err != nil {
		fmt.Println("error when init test signer")
	}

	round2msg := append(m1, n2...)
	r2sig, err := signer.Sign(round2msg)
	if err != nil {
		fmt.Println("error when sign round2 message")
	}

	end_1 := time.Since(start_1)
	fmt.Printf("time cost = %v\n", end_1)

	verifier, err := note.NewVerifier(testAttPublicKey)
	if err != nil {
		fmt.Println("error when init test signer")
	}

	if !verifier.Verify(round2msg, r2sig) {
		fmt.Println("error when verify the round2 signature")
	}

	/*------------------------- Round 3 -------------------------*/
	// recover hc_D
	h = sha256.New()
	h.Write(real_cert.RawTBSCertificate)
	h.Write(decoded_entry.Ts)
	h.Write([]byte(real_cert.Issuer.CommonName))
	hc_ca := h.Sum(nil)
	fmt.Println("Recover hc_D", hc_ca, hc)

	// recover rl
	h = sha256.New()
	h.Write(hc)
	h.Write(n1)
	temph = h.Sum(nil)

	rl_ca := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rl_ca[i] = temph[i] ^ m1[i]
	}
	fmt.Println("Recover rl", rl_ca, rl)

	// generate RD
	testPUF := &putil.SimPUF{
		PUF_ID: []byte("attestation"),
	}
	rd := testPUF.GetResponse(hc_ca)

	// generate m2
	h = sha256.New()
	h.Write(rl_ca)
	h.Write(raw_entry)
	h.Write(n2)
	temph = h.Sum(nil)

	m2 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		m2[i] = temph[i] ^ rd[i]
	}

	/*------------------------- Final Verify -------------------------*/
	start_2 := time.Now()
	// recover rd
	h = sha256.New()
	h.Write(rl)
	h.Write(raw_entry)
	h.Write(n2)
	temph = h.Sum(nil)

	rd_lgr := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rd_lgr[i] = temph[i] ^ m2[i]
	}
	end_2 := time.Since(start_2)
	fmt.Printf("time cost = %v\n", end_2)
	fmt.Println("Overall: ", end_1.Microseconds()+end_2.Microseconds())

	fmt.Println("Final output: ", rd_lgr, rd)

}
