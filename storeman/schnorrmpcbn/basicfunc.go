package schnorrmpcbn

import (
	Rand "crypto/rand"
	"github.com/wanchain/schnorr-mpc/crypto/bn256/cloudflare"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

// Generator of ECC
var gbase = new(bn256.G1).ScalarBaseMult(big.NewInt(int64(1)))

type BnSchnorrMpc struct {
}

func NewBnSchnorrMpc() *BnSchnorrMpc {
	return &BnSchnorrMpc{}
}

func (bsm *BnSchnorrMpc) RandPoly(degree int, constant big.Int) mpcprotocol.Polynomial {
	return RandPoly(degree, constant)
}

func (bsm *BnSchnorrMpc) EvaluatePoly(f mpcprotocol.Polynomial, x *big.Int, degree int) big.Int {
	return EvaluatePoly(f, x, degree)
}

func (bsm *BnSchnorrMpc) Equal(left, right mpcprotocol.CurvePointer) bool {
	return true
}

func (bsm *BnSchnorrMpc) IsOnCurve(pt mpcprotocol.CurvePointer) bool {
	return true
}

func (bsm *BnSchnorrMpc) SkG(sk *big.Int) (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) MulPK(sk *big.Int, pk mpcprotocol.CurvePointer) (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) Add(left, right mpcprotocol.CurvePointer) (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) NewPt() (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) MarshPt(pt mpcprotocol.CurvePointer) ([]byte, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) UnMarshPt(b []byte) (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) PtToHexString(pt mpcprotocol.CurvePointer) string {
	return ""
}

func (bsm *BnSchnorrMpc) StringToPt(str string) (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) PtByteLen() int {
	return 64
}

func (bsm *BnSchnorrMpc) GetMod() *big.Int {
	return bn256.Order
}

func (bsm *BnSchnorrMpc) SplitPksFromBytes(buf []byte) ([]mpcprotocol.CurvePointer, error) {
	return nil, nil
}
func (bsm *BnSchnorrMpc) EvalByPolyG([]mpcprotocol.CurvePointer, uint16, *big.Int) (mpcprotocol.CurvePointer, error) {
	return nil, nil
}

func (bsm *BnSchnorrMpc) SchnorrSign(psk big.Int, r big.Int, m big.Int) big.Int {
	return SchnorrSign(psk, r, m)
}

func (bsm *BnSchnorrMpc) Lagrange(f []big.Int, x []big.Int, degree int) big.Int {
	return Lagrange(f, x, degree)
}

// Generate a random polynomial, its constant item is nominated
func RandPoly(degree int, constant big.Int) mpcprotocol.Polynomial {

	poly := make(mpcprotocol.Polynomial, degree+1)

	poly[0].Mod(&constant, bn256.Order)

	for i := 1; i < degree+1; i++ {

		temp, _ := Rand.Int(Rand.Reader, bn256.Order)

		// in case of polynomial degenerating
		poly[i] = *temp.Add(temp, schcomm.BigOne)
	}
	return poly
}

// Calculate polynomial's evaluation at some point
func EvaluatePoly(f mpcprotocol.Polynomial, x *big.Int, degree int) big.Int {

	sum := big.NewInt(0)

	for i := 0; i < degree+1; i++ {

		temp1 := new(big.Int).Exp(x, big.NewInt(int64(i)), bn256.Order)

		temp1.Mod(temp1, bn256.Order)

		temp2 := new(big.Int).Mul(&f[i], temp1)

		temp2.Mod(temp2, bn256.Order)

		sum.Add(sum, temp2)

		sum.Mod(sum, bn256.Order)
	}
	return *sum
}

// Calculate the b coefficient in Lagrange's polynomial interpolation algorithm

func evaluateB(x []big.Int, degree int) []big.Int {

	//k := len(x)

	k := degree + 1

	b := make([]big.Int, k)

	for i := 0; i < k; i++ {
		b[i] = evaluateb(x, i, degree)
	}
	return b
}

// sub-function for evaluateB

func evaluateb(x []big.Int, i int, degree int) big.Int {

	//k := len(x)

	k := degree + 1

	sum := big.NewInt(1)

	for j := 0; j < k; j++ {

		if j != i {

			temp1 := new(big.Int).Sub(&x[j], &x[i])

			temp1.ModInverse(temp1, bn256.Order)

			temp2 := new(big.Int).Mul(&x[j], temp1)

			sum.Mul(sum, temp2)

			sum.Mod(sum, bn256.Order)

		} else {
			continue
		}
	}
	return *sum
}

// Lagrange's polynomial interpolation algorithm: working in ECC points
func LagrangeECC(sig []*bn256.G1, x []big.Int, degree int) bn256.G1 {

	b := evaluateB(x, degree)

	sum := new(bn256.G1).ScalarBaseMult(big.NewInt(int64(0)))

	for i := 0; i < degree+1; i++ {
		temp := new(bn256.G1).ScalarMult(sig[i], &b[i])
		sum.Add(sum, temp)
	}
	return *sum
}

func SchnorrSign(psk big.Int, r big.Int, m big.Int) big.Int {
	sum := big.NewInt(1)
	sum.Mul(&psk, &m)
	sum.Mod(sum, bn256.Order)
	sum.Add(sum, &r)
	sum.Mod(sum, bn256.Order)
	return *sum
}

// Lagrange's polynomial interpolation algorithm
func Lagrange(f []big.Int, x []big.Int, degree int) big.Int {

	b := evaluateB(x, degree)

	s := big.NewInt(0)

	for i := 0; i < degree+1; i++ {

		temp1 := new(big.Int).Mul(&f[i], &b[i])

		s.Add(s, temp1)

		s.Mod(s, bn256.Order)
	}
	return *s
}

// The comparison function of G1
func CompareG1(a bn256.G1, b bn256.G1) bool {
	return a.String() == b.String()
}
