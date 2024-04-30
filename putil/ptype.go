package putil

type IssuerType int32

const (
	RootCA         IssuerType = 0
	IntermediateCA IssuerType = 1
	LeafCA         IssuerType = 2
)

type IssueInfo struct {
	IType       IssuerType
	ITime       []byte
	ResponseSig []byte  // R used in sig
	HashPointer []byte  // h_{CA}
	PUFInst     *SimPUF // the used PUF instance
	PubPUFProof []byte  // the proof \pi for CA
	ProvChall   []byte  // proving challenge C_{CA}
}

type LevelOut struct {
	ResponseSig []byte
	HashPointer []byte
	CompRP      []byte
}
