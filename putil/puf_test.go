package putil

import (
	"fmt"
	"testing"
)

func TestSimPUF(t *testing.T) {
	puf := &SimPUF{
		PUF_ID: GenRandomBytes(PUF_ID_LENGTH),
	}

	challenge := GenRandomBytes(PUF_LENGTH)

	// Compute the response for the challenge

	//start := time.Now()
	response := puf.GetResponse(challenge) // ~2.5µs
	//cost := time.Since(start)
	fmt.Println("Challenge: ", challenge)
	fmt.Println("Response: ", response)
}
