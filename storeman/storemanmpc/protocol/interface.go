package protocol

import (
	"math/big"
)

var BigZero = big.NewInt(0)

var BigOne = big.NewInt(1)

// Structure defination for polynomial
type Polynomial []big.Int

// polynomial commit
//type PolynomialG []ecdsa.PublicKey
type PolynomialG []CurvePointer
type PolynomialGSig []big.Int

// key: 	smIndex
// value: 	polyCommitG
type PolyGMap map[uint16]PolynomialG
type PolyGSigMap map[uint16]PolynomialGSig

type MpcResultInterface interface {
	Initialize() error
	SetValue(key string, value []big.Int) error
	GetValue(key string) ([]big.Int, error)
	SetByteValue(key string, value []byte) error
	GetByteValue(key string) ([]byte, error)
}

type CurvePointer interface {
}

type SchnorrMPCer interface {
	RandPoly(degree int, constant big.Int) Polynomial
	EvaluatePoly(f Polynomial, x *big.Int, degree int) big.Int
	//LagrangeECC(sig []ecdsa.PublicKey, x []big.Int, degree int) *ecdsa.PublicKey
	//SchnorrSign(psk big.Int, r big.Int, m big.Int) big.Int
	//Lagrange(f []big.Int, x []big.Int, degree int) big.Int

	Equal(left, right CurvePointer) bool
	IsOnCurve(pt CurvePointer) bool
	SkG(sk *big.Int) (CurvePointer, error)
	MulPK(sk *big.Int, pk CurvePointer) (CurvePointer, error)
	Add(left, right CurvePointer) (CurvePointer, error)
	NewPt() (CurvePointer, error)
	MarshPt(pt CurvePointer) ([]byte, error)
	UnMarshPt(b []byte) (CurvePointer, error)
	PtToHexString(CurvePointer) string
	StringToPt(string) (CurvePointer, error)
	PtByteLen() int
}

type MpcContexter interface {
	GetSchnorrMPCer() SchnorrMPCer
}
