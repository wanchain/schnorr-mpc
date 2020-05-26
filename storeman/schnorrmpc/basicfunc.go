package schnorrmpc

import (
	"crypto/ecdsa"
	Rand "crypto/rand"
	"errors"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

const PkLength = 65

var BigOne = big.NewInt(1)
var BigZero = big.NewInt(0)

// Generate a random polynomial, its constant item is nominated
func RandPoly(degree int, constant big.Int) Polynomial {

	poly := make(Polynomial, degree+1)

	poly[0].Mod(&constant, crypto.S256().Params().N)

	for i := 1; i < degree+1; i++ {

		temp, _ := Rand.Int(Rand.Reader, crypto.S256().Params().N)

		// in case of polynomial degenerating
		poly[i] = *temp.Add(temp, bigOne)
	}
	return poly
}

// Calculate polynomial's evaluation at some point
func EvaluatePoly(f Polynomial, x *big.Int, degree int) big.Int {

	sum := big.NewInt(0)

	for i := 0; i < degree+1; i++ {

		temp1 := new(big.Int).Exp(x, big.NewInt(int64(i)), crypto.S256().Params().N)

		temp1.Mod(temp1, crypto.S256().Params().N)

		temp2 := new(big.Int).Mul(&f[i], temp1)

		temp2.Mod(temp2, crypto.S256().Params().N)

		sum.Add(sum, temp2)

		sum.Mod(sum, crypto.S256().Params().N)
	}
	return *sum
}

// Calculate the b coefficient in Lagrange's polynomial interpolation algorithm

func evaluateB(x []big.Int, degree int) []*big.Int {

	//k := len(x)

	k := degree + 1

	b := make([]*big.Int, k)

	for i := 0; i < k; i++ {
		b[i] = evaluateb(x, i, degree)
	}
	return b
}

// sub-function for evaluateB

func evaluateb(x []big.Int, i int, degree int) *big.Int {

	//k := len(x)

	k := degree + 1

	sum := big.NewInt(1)

	for j := 0; j < k; j++ {

		if j != i {

			temp1 := new(big.Int).Sub(&x[j], &x[i])

			temp1.ModInverse(temp1, crypto.S256().Params().N)

			temp2 := new(big.Int).Mul(&x[j], temp1)

			sum.Mul(sum, temp2)

			sum.Mod(sum, crypto.S256().Params().N)

		} else {
			continue
		}
	}
	return sum
}

// Lagrange's polynomial interpolation algorithm: working in ECC points
func LagrangeECC(sig []ecdsa.PublicKey, x []big.Int, degree int) *ecdsa.PublicKey {

	b := evaluateB(x, degree)

	sum := new(ecdsa.PublicKey)
	sum.X, sum.Y = crypto.S256().ScalarMult(sig[0].X, sig[0].Y, b[0].Bytes())

	for i := 1; i < degree+1; i++ {
		temp := new(ecdsa.PublicKey)
		temp.X, temp.Y = crypto.S256().ScalarMult(sig[i].X, sig[i].Y, b[i].Bytes())
		sum.X, sum.Y = crypto.S256().Add(sum.X, sum.Y, temp.X, temp.Y)
	}
	return sum
}

func SchnorrSign(psk big.Int, r big.Int, m big.Int) big.Int {
	// sshare = rskshare + m*gskSahre
	sum := big.NewInt(1)
	sum.Mul(&psk, &m)
	sum.Mod(sum, crypto.S256().Params().N)
	sum.Add(sum, &r)
	sum.Mod(sum, crypto.S256().Params().N)
	return *sum
}

// Lagrange's polynomial interpolation algorithm
func Lagrange(f []big.Int, x []big.Int, degree int) big.Int {

	b := evaluateB(x, degree)

	s := big.NewInt(0)

	for i := 0; i < degree+1; i++ {

		temp1 := new(big.Int).Mul(&f[i], b[i])

		s.Add(s, temp1)

		s.Mod(s, crypto.S256().Params().N)
	}
	return *s
}

func ValidatePublicKey(k *ecdsa.PublicKey) bool {
	return k != nil && k.X != nil && k.Y != nil && k.X.Sign() != 0 && k.Y.Sign() != 0
}

func UintRand(MaxValue uint64) (uint64, error) {
	num, err := Rand.Int(Rand.Reader, new(big.Int).SetUint64(MaxValue))
	if err != nil {
		return 0, err
	}

	return num.Uint64(), nil
}

func PkToAddress(PkBytes []byte) (common.Address, error) {
	if len(PkBytes) != PkLength {
		return common.Address{}, errors.New("invalid pk address")
	}
	pk := crypto.ToECDSAPub(PkBytes[:])
	address := crypto.PubkeyToAddress(*pk)
	return address, nil
}

func PkToHexString(pk *ecdsa.PublicKey) string {
	pkByte := crypto.FromECDSAPub(pk)
	return hexutil.Encode(pkByte)
}

func StringtoPk(str string) (*ecdsa.PublicKey, error) {
	pkBytes, err := hexutil.Decode(str)
	if err != nil {
		return nil, err
	}
	pk := crypto.ToECDSAPub(pkBytes)
	return pk, nil
}

//sg
func SkG(s *big.Int) (*ecdsa.PublicKey, error) {
	sG := new(ecdsa.PublicKey)
	sG.Curve = crypto.S256()
	sG.X, sG.Y = crypto.S256().ScalarBaseMult(s.Bytes())
	return sG, nil
}

func SkMul(pk *ecdsa.PublicKey, s *big.Int) (*ecdsa.PublicKey, error) {

	ret := new(ecdsa.PublicKey)
	ret.Curve = crypto.S256()

	ret.X, ret.Y = crypto.S256().ScalarMult(pk.X, pk.Y, s.Bytes())
	return ret, nil
}

//
func SplitPksFromBytes(buf []byte) ([]*ecdsa.PublicKey, error) {
	nPk := len(buf) / PkLength
	ret := make([]*ecdsa.PublicKey, nPk)
	for i := 0; i < nPk; i++ {
		onePkBytes := buf[i*PkLength : (i+1)*PkLength]
		onePk := crypto.ToECDSAPub(onePkBytes[:])
		ret[i] = onePk
	}
	return ret, nil
}

func EvalByPolyG(pks []*ecdsa.PublicKey, degree uint16, x *big.Int) (*ecdsa.PublicKey, error) {
	// check input parameters

	sumPk := new(ecdsa.PublicKey)
	sumPk.Curve = crypto.S256()
	sumPk.X, sumPk.Y = pks[0].X, pks[0].Y

	for i := 1; i < int(degree)+1; i++ {

		temp1 := new(big.Int).Exp(x, big.NewInt(int64(i)), crypto.S256().Params().N)
		temp1.Mod(temp1, crypto.S256().Params().N)

		temp1Pk := new(ecdsa.PublicKey)
		temp1Pk.Curve = crypto.S256()

		temp1Pk.X, temp1Pk.Y = crypto.S256().ScalarMult(pks[i].X, pks[i].Y, temp1.Bytes())

		sumPk.X, sumPk.Y = crypto.S256().Add(sumPk.X, sumPk.Y, temp1Pk.X, temp1Pk.Y)

	}
	return sumPk, nil
}

func PkEqual(pk1, pk2 *ecdsa.PublicKey) (bool, error) {
	// check input parameters
	return pk1.X.Cmp(pk2.X) == 0 && pk1.Y.Cmp(pk2.Y) == 0, nil
}

func SignInternalData(prv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(Rand.Reader, prv, hash[:])
}

func VerifyInternalData(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	return ecdsa.Verify(pub, hash, r, s)
}

func CheckPK(pk *ecdsa.PublicKey) error {
	if pk == nil {
		return protocol.ErrInvalidPK
	}
	if !crypto.S256().IsOnCurve(pk.X, pk.Y) {
		return protocol.ErrInvalidPK
	} else {
		return nil
	}
}
