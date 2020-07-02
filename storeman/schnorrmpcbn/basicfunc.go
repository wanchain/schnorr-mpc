package schnorrmpcbn

import (
	Rand "crypto/rand"
	"errors"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto/bn256/cloudflare"
	"github.com/wanchain/schnorr-mpc/log"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

const pkLengthBn = 64

// Generator of ECC
var gbase = new(bn256.G1).ScalarBaseMult(big.NewInt(int64(1)))

type BnSchnorrMpc struct {
}

func NewBnSchnorrMpc() *BnSchnorrMpc {
	return &BnSchnorrMpc{}
}

func (bsm *BnSchnorrMpc) RandPoly(degree int, constant big.Int) mpcprotocol.Polynomial {
	log.SyslogDebug("Entering BN RandPoly")
	return randPoly(degree, constant)
}

func (bsm *BnSchnorrMpc) EvaluatePoly(f mpcprotocol.Polynomial, x *big.Int, degree int) big.Int {
	log.SyslogDebug("Entering BN EvaluatePoly")
	return evaluatePoly(f, x, degree)
}

func (bsm *BnSchnorrMpc) Equal(left, right mpcprotocol.CurvePointer) bool {
	log.SyslogDebug("Entering BN Equal")
	ptLeft, ok := left.(*bn256.G1)
	if !ok {
		fmt.Println("It's not ok for type bn256.G1")
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return false
	}

	ptRight, ok := left.(*bn256.G1)
	if !ok {
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return false
	}
	return compareG1(ptLeft, ptRight)
}

func (bsm *BnSchnorrMpc) IsOnCurve(pt mpcprotocol.CurvePointer) bool {
	log.SyslogDebug("Entering BN IsOnCurve")
	ptTemp, ok := pt.(*bn256.G1)
	if !ok {
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return false
	}

	if ptTemp == nil {
		return false
	}
	return ptTemp.IsOnCurve()
}

func (bsm *BnSchnorrMpc) SkG(sk *big.Int) (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN SkG")
	return new(bn256.G1).ScalarBaseMult(sk), nil
}

func (bsm *BnSchnorrMpc) MulPK(sk *big.Int, pk mpcprotocol.CurvePointer) (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN MulPK")
	pt, ok := pk.(*bn256.G1)
	if !ok {
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return nil, mpcprotocol.ErrTypeAssertFail
	}
	return new(bn256.G1).ScalarMult(pt, sk), nil
}

func (bsm *BnSchnorrMpc) Add(left, right mpcprotocol.CurvePointer) (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN Add")
	ptLeft, ok := left.(*bn256.G1)
	if !ok {
		fmt.Println("It's not ok for type bn256.G1")
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return nil, mpcprotocol.ErrTypeAssertFail
	}

	ptRight, ok := left.(*bn256.G1)
	if !ok {
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return nil, mpcprotocol.ErrTypeAssertFail
	}
	return new(bn256.G1).Add(ptLeft, ptRight), nil
}

func (bsm *BnSchnorrMpc) NewPt() (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN NewPt")
	return new(bn256.G1), nil
}

func (bsm *BnSchnorrMpc) MarshPt(pt mpcprotocol.CurvePointer) ([]byte, error) {
	log.SyslogDebug("Entering BN MarshPt")
	ptTemp, ok := pt.(*bn256.G1)
	if !ok {
		errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
		log.SyslogErr(errStr)
		return nil, mpcprotocol.ErrTypeAssertFail
	}
	return ptTemp.Marshal(), nil

}

func (bsm *BnSchnorrMpc) UnMarshPt(b []byte) (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN UnMarshPt")
	ptRet := new(bn256.G1)
	_, err := ptRet.Unmarshal(b)
	if err != nil {
		errStr := fmt.Sprintf("From byte to pt, error:%s", err.Error())
		return nil, errors.New(errStr)
	}
	return ptRet, nil
}

func (bsm *BnSchnorrMpc) PtToHexString(pt mpcprotocol.CurvePointer) string {
	log.SyslogDebug("Entering BN PtToHexString")
	b, err := bsm.MarshPt(pt)
	if err != nil {
		return ""
	} else {
		return hexutil.Encode(b)
	}
}

func (bsm *BnSchnorrMpc) PtByteLen() int {
	log.SyslogDebug("Entering BN PtByteLen")
	return pkLengthBn
}

func (bsm *BnSchnorrMpc) GetMod() *big.Int {
	log.SyslogDebug("Entering BN GetMod")
	return bn256.Order
}

func (bsm *BnSchnorrMpc) StringToPt(str string) (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN StringToPt")
	pkBytes, err := hexutil.Decode(str)
	if err != nil {
		return nil, err
	}

	if len(pkBytes) != pkLengthBn {
		return nil, errors.New(fmt.Sprintf("len(pkBytes)= %v error. ", len(pkBytes)))
	}
	return bsm.UnMarshPt(pkBytes)
}

func (bsm *BnSchnorrMpc) SplitPksFromBytes(buf []byte) ([]mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN SplitPksFromBytes")
	ret := make([]mpcprotocol.CurvePointer, 0)
	ret1, err := splitPksFromBytes(buf[:])
	for _, pt := range ret1 {
		ret = append(ret, pt)
	}
	return ret, err
}

func (bsm *BnSchnorrMpc) EvalByPolyG(pts []mpcprotocol.CurvePointer, degree uint16, xvalue *big.Int) (mpcprotocol.CurvePointer, error) {
	log.SyslogDebug("Entering BN EvalByPolyG")
	pks := make([]*bn256.G1, 0)
	for _, pt := range pts {
		ptTemp, ok := pt.(*bn256.G1)
		if !ok {
			errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
			log.SyslogErr(errStr)
			return nil, mpcprotocol.ErrTypeAssertFail
		}
		pks = append(pks, ptTemp)
	}
	return evalByPolyG(pks, degree, xvalue)
}

func (bsm *BnSchnorrMpc) SchnorrSign(psk big.Int, r big.Int, m big.Int) big.Int {
	log.SyslogDebug("Entering BN SchnorrSign")
	return schnorrSign(psk, r, m)
}

func (bsm *BnSchnorrMpc) Lagrange(f []big.Int, x []big.Int, degree int) big.Int {
	log.SyslogDebug("Entering BN Lagrange")
	return lagrange(f, x, degree)
}

func (bsm *BnSchnorrMpc) LagrangeECC(sig []mpcprotocol.CurvePointer, x []big.Int, degree int) mpcprotocol.CurvePointer {
	log.SyslogDebug("Entering BN LagrangeECC")
	sigSecBn := make([]*bn256.G1, 0)
	for _, oneSig := range sig {
		pTemp, ok := oneSig.(*bn256.G1)
		if !ok {
			fmt.Println("It's not ok for type ecdsa.PublicKey")
			errStr := fmt.Sprintf("From CurvePointer to PublicKey, error:%s", mpcprotocol.ErrTypeAssertFail)
			log.SyslogErr(errStr)
			return nil
		}

		sigSecBn = append(sigSecBn, pTemp)
	}

	return lagrangeECC(sigSecBn, x, degree)
}

// Generate a random polynomial, its constant item is nominated
func randPoly(degree int, constant big.Int) mpcprotocol.Polynomial {

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
func evaluatePoly(f mpcprotocol.Polynomial, x *big.Int, degree int) big.Int {

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
func lagrangeECC(sig []*bn256.G1, x []big.Int, degree int) *bn256.G1 {

	b := evaluateB(x, degree)

	sum := new(bn256.G1).ScalarBaseMult(big.NewInt(int64(0)))

	for i := 0; i < degree+1; i++ {
		temp := new(bn256.G1).ScalarMult(sig[i], &b[i])
		sum.Add(sum, temp)
	}
	return sum
}

func splitPksFromBytes(buf []byte) ([]*bn256.G1, error) {
	if len(buf) < pkLengthBn {
		return nil, errors.New(fmt.Sprintf("SplitPksFromBytes len(buf) = %v", len(buf)))
	}
	nPk := len(buf) / pkLengthBn
	ret := make([]*bn256.G1, nPk)
	for i := 0; i < nPk; i++ {
		onePkBytes := buf[i*pkLengthBn : (i+1)*pkLengthBn]
		onePk := new(bn256.G1)
		_, err := onePk.Unmarshal(onePkBytes)
		if err != nil {
			log.SyslogErr("bn splitPksFromBytes", "err", err.Error())
			return nil, err
		}
		ret[i] = onePk
	}
	return ret, nil
}

func schnorrSign(psk big.Int, r big.Int, m big.Int) big.Int {
	sum := big.NewInt(1)
	sum.Mul(&psk, &m)
	sum.Mod(sum, bn256.Order)
	sum.Add(sum, &r)
	sum.Mod(sum, bn256.Order)
	return *sum
}

// Lagrange's polynomial interpolation algorithm
func lagrange(f []big.Int, x []big.Int, degree int) big.Int {

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
func compareG1(a *bn256.G1, b *bn256.G1) bool {
	return a.String() == b.String()
}

func evalByPolyG(pks []*bn256.G1, degree uint16, x *big.Int) (*bn256.G1, error) {
	if len(pks) == 0 || x.Cmp(schcomm.BigZero) == 0 {
		return nil, errors.New("len(pks)==0 or xvalue is zero")
	}
	if len(pks) != int(degree+1) {
		return nil, errors.New("degree is not content with the len(pks)")
	}

	for _, pk := range pks {
		if !pk.IsOnCurve() {
			return nil, errors.New("bn Pt is not on curve")
		}

	}
	sumPk := new(bn256.G1)
	for i := 0; i < int(degree)+1; i++ {

		temp1 := new(big.Int).Exp(x, big.NewInt(int64(i)), bn256.Order)
		temp1.Mod(temp1, bn256.Order)

		temp1Pk := new(bn256.G1).ScalarMult(pks[i], temp1)
		sumPk.Add(sumPk, temp1Pk)
	}
	return sumPk, nil
}
