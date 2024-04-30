package trclient

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/letsencrypt/pebble/v2/putil"
	"github.com/letsencrypt/pebble/v2/trclient/personality"
	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

const (
	// testPrivateKey is the personality's key for signing its checkpoints.
	testPrivateKey = "PRIVATE+KEY+helloworld+b51acf1b+ASW28PXJDCV8klh7JeacIgfJR3/Q60dklasmgnv4c9I7"
	// testPublicKey is used for verifying the signatures on the checkpoints from
	// the personality.
	testPublicKey = "helloworld+b51acf1b+AZ2ZM0ZQ69GwDUyO7/x0JyLo09y3geyufyN1mFFMeUH3"
)

var TC *personality.TrillianClient
var CTX context.Context

func mustGetSigner() note.Signer {
	s, err := note.NewSigner(testPrivateKey)
	if err != nil {
		fmt.Printf("Failed to create signer: %q \n", err)
	}
	return s
}

func mustGetVerifier() note.Verifier {
	v, err := note.NewVerifier(testPublicKey)
	if err != nil {
		fmt.Printf("Failed to create verifier: %q \n", err)
	}
	return v
}

func MustOpenCheckpoint(cRaw []byte) *log.Checkpoint {
	cp, _, _, err := log.ParseCheckpoint(cRaw, "Hello World Log", mustGetVerifier())
	if err != nil {
		fmt.Printf("Failed to open checkpoint: %q \n", err)
	}
	return cp
}

func CreatePUFEntry(caname string, info putil.IssueInfo, resp []byte, proof []byte, crt []byte) ([]byte, error) {

	//start := time.Now()
	zbytes := [][]byte{[]byte(caname), []byte(PUFManu), info.ITime, info.PUFInst.PUF_ID, proof}
	var aux_z_bytes []byte
	for _, item := range zbytes {
		aux_z_bytes = append(aux_z_bytes, item...)
	}
	// need R, need last T, need crt

	h := sha256.New()

	h.Write(resp)
	h.Write(aux_z_bytes)
	h.Write(crt)
	h.Write(TC.LastTag)

	new_tag := h.Sum(nil)
	//fmt.Println("Lasttag", TC.LastTag, hex.EncodeToString(TC.LastTag))
	//fmt.Println("Hash entry tag", hex.EncodeToString(resp), hex.EncodeToString(aux_z_bytes), hex.EncodeToString(crt), hex.EncodeToString(TC.LastTag), hex.EncodeToString(new_tag[:10]))

	entry := &PUFEntry{
		Caname: caname,
		Manu:   PUFManu,
		Ts:     info.ITime,
		Pufid:  info.PUFInst.PUF_ID,
		Comrp:  proof,
		Tag:    new_tag,
	}
	entry_bytes, err := proto.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to create PUF entry using protobuf %q", err)
	}
	//fmt.Println("In CreatePUFEntry ", caname, entry_bytes[:16])
	TC.Counter += 1
	TC.LastTag = new_tag
	// end := time.Since(start)
	// fmt.Println("measure: ", end.Microseconds())

	return entry_bytes, nil
}

func AppendEntry(entry []byte) error {
	//start := time.Now()
	chkptNewRaw, err := TC.Append(CTX, entry)
	if err != nil {
		return fmt.Errorf("failed to append new entry %q", err)
	}
	//end := time.Since(start)
	//fmt.Println("measure: ", end.Microseconds())

	chkpt := MustOpenCheckpoint(chkptNewRaw)
	fmt.Println("In AppendEntry", chkpt.Size)
	if chkpt.Size == 0 {
		return fmt.Errorf("something wrong during appending")
	}

	return nil
}

func InitTrillainClient(loggerAddress string, treeID int64) {
	var err error
	TC, err = personality.NewPersonality(loggerAddress, treeID, mustGetSigner())
	CTX = context.Background()
	if err != nil {
		fmt.Printf("Failed to create Trillian Personality Client: %q \n", err)
	}
}
