package putil

import (
	"crypto/rand"
	"crypto/sha256"
)

type PUF interface {
	get_response(challenge string) string
}

const (
	PUF_LENGTH    int = 32
	PUF_ID_LENGTH int = 4
)

type PubProof []byte

/*
a simulated PUF interface
*/
type SimPUF struct {
	PUF_ID []byte // unique id to generate different responses
}

func GenRandomBytes(length int) []byte {
	rd := make([]byte, length)
	_, err := rand.Read(rd)
	if err != nil {
		return nil
	}
	return rd
}

func InitPUFs(nums int) []*SimPUF {
	var pufs []*SimPUF
	for i := 0; i < nums; i++ {
		id := GenRandomBytes(PUF_ID_LENGTH)
		puf := SimPUF{PUF_ID: id}
		pufs = append(pufs, &puf)
	}
	return pufs
}

func (p *SimPUF) GetResponse(challenge []byte) []byte {
	input := append(p.PUF_ID, challenge...)
	resp := sha256.Sum256(input)
	return resp[:]
}
