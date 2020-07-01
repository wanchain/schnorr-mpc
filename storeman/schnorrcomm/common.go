package schnorrcomm

import (
	"crypto/ecdsa"
	Rand "crypto/rand"
	"github.com/wanchain/schnorr-mpc/crypto"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

var BigOne = big.NewInt(1)
var BigZero = big.NewInt(0)

var PocTest = true

func SignInternalData(prv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(Rand.Reader, prv, hash[:])
}

func VerifyInternalData(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	return ecdsa.Verify(pub, hash, r, s)
}

func CheckPK(pk *ecdsa.PublicKey) error {
	if pk == nil {
		return mpcprotocol.ErrInvalidPK
	}
	if !crypto.S256().IsOnCurve(pk.X, pk.Y) {
		return mpcprotocol.ErrInvalidPK
	} else {
		return nil
	}
}

func UintRand(MaxValue uint64) (uint64, error) {
	num, err := Rand.Int(Rand.Reader, new(big.Int).SetUint64(MaxValue))
	if err != nil {
		return 0, err
	}

	return num.Uint64(), nil
}
