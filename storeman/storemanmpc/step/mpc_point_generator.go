package step

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/shcnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type mpcPointGenerator struct {
	seed        [2]big.Int
	message     map[uint64][2]big.Int
	result      [2]big.Int
	preValueKey string
}

func createPointGenerator(preValueKey string) *mpcPointGenerator {
	return &mpcPointGenerator{message: make(map[uint64][2]big.Int), preValueKey: preValueKey}
}

func (point *mpcPointGenerator) initialize(peers *[]mpcprotocol.PeerInfo, result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("mpcPointGenerator.initialize begin ")

	value, err := result.GetValue(point.preValueKey)
	log.SyslogInfo("public share mpcPointGenerator.initialize GetValue ",
		"key", point.preValueKey,
		"pk share x", hex.EncodeToString(value[0].Bytes()),
		"pk share y", hex.EncodeToString(value[1].Bytes()))

	if err != nil {
		log.SyslogErr("mpcPointGenerator.initialize get preValueKey fail")
		return err
	}

	point.seed = [2]big.Int{value[0], value[1]}

	log.SyslogInfo("mpcPointGenerator.initialize succeed")
	return nil
}

func (point *mpcPointGenerator) calculateResult() error {
	log.SyslogInfo("mpcPointGenerator.calculateResult begin")

	seeds := make([]big.Int, 0)
	gpkshares := make([]ecdsa.PublicKey, 0)
	for seed, value := range point.message {

		// get seeds, need sort seeds, and make seeds as a key of map, and check the map's count??
		seeds = append(seeds, *big.NewInt(0).SetUint64(seed))

		// build PK[]
		var gpkshare ecdsa.PublicKey
		gpkshare.Curve = crypto.S256()

		gpkshare.X = big.NewInt(0).SetBytes(value[0].Bytes())
		gpkshare.Y = big.NewInt(0).SetBytes(value[1].Bytes())

		gpkshares = append(gpkshares, gpkshare)

	}

	for index, gpkshareTemp := range gpkshares {
		log.SyslogInfo("all public share",
			"gpk share x", hex.EncodeToString(gpkshareTemp.X.Bytes()),
			"gpk share y", hex.EncodeToString(gpkshareTemp.Y.Bytes()),
			"seed", hex.EncodeToString(seeds[index].Bytes()))
	}

	// lagrangeEcc
	log.SyslogInfo("all public",
		"Need nodes number:", mpcprotocol.MpcSchnrThr,
		"Now nodes number:", len(gpkshares))
	if len(gpkshares) < mpcprotocol.MpcSchnrThr {
		return mpcprotocol.ErrTooLessDataCollected
	}

	result := shcnorrmpc.LagrangeECC(gpkshares, seeds[:], mpcprotocol.MPCDegree)

	if !shcnorrmpc.ValidatePublicKey(result) {
		log.SyslogErr("mpcPointGenerator::calculateResult","mpcPointGenerator.ValidatePublicKey fail. err", mpcprotocol.ErrPointZero.Error())
		return mpcprotocol.ErrPointZero
	}

	point.result = [2]big.Int{*result.X, *result.Y}

	log.SyslogInfo("gpk mpcPointGenerator.calculateResult succeed ",
		"gpk x", hex.EncodeToString(point.result[0].Bytes()),
		"gpk y", hex.EncodeToString(point.result[1].Bytes()))
	return nil
}
