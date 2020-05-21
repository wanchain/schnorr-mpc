package step

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type mpcPointGenerator struct {
	seed        ecdsa.PublicKey
	message     map[discover.NodeID]ecdsa.PublicKey
	result 		ecdsa.PublicKey
	preValueKey string
	grpIdString	string
}

func createPointGenerator(preValueKey string) *mpcPointGenerator {
	return &mpcPointGenerator{message: make(map[discover.NodeID]ecdsa.PublicKey), preValueKey: preValueKey}
}

func (point *mpcPointGenerator) initialize(peers *[]mpcprotocol.PeerInfo, result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("mpcPointGenerator.initialize begin ")

	// get self rpkshare
	_, grpIdString, _ := osmconf.GetGrpId(result)

	point.grpIdString = grpIdString

	selfIndex,_ := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	key := mpcprotocol.RPkShare + strconv.Itoa(int(selfIndex))
	value, err := result.GetByteValue(key)

	log.SyslogInfo("public share mpcPointGenerator.initialize GetValue ",
		"key", point.preValueKey,
		"pk share ", hex.EncodeToString(value))

	if err != nil {
		log.SyslogErr("mpcPointGenerator.initialize get preValueKey fail")
		return err
	}

	point.seed = *crypto.ToECDSAPub(value)

	log.SyslogInfo("mpcPointGenerator.initialize succeed")
	return nil
}

func (point *mpcPointGenerator) calculateResult() error {
	log.SyslogInfo("mpcPointGenerator.calculateResult begin")

	seeds := make([]big.Int, 0)
	gpkshares := make([]ecdsa.PublicKey, 0)
	for nodeId, value := range point.message {

		xValue,_ := osmconf.GetOsmConf().GetXValueByNodeId(point.grpIdString,&nodeId)
		seeds = append(seeds, *xValue)

		// build PK[]
		var gpkshare ecdsa.PublicKey
		gpkshare.Curve = crypto.S256()

		gpkshare.X = value.X
		gpkshare.Y = value.Y

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
		//return mpcprotocol.ErrTooLessDataCollected

		if ok,_ := osmconf.GetOsmConf().IsLeader(point.grpIdString);ok{
			// only leader invoke the errRNW and response to client.
			return mpcprotocol.ErrRNW
		}else{
			return nil
		}
	}

	result := schnorrmpc.LagrangeECC(gpkshares, seeds[:], mpcprotocol.MPCDegree)

	if !schnorrmpc.ValidatePublicKey(result) {
		log.SyslogErr("mpcPointGenerator::calculateResult","mpcPointGenerator.ValidatePublicKey fail. err", mpcprotocol.ErrPointZero.Error())
		return mpcprotocol.ErrPointZero
	}

	point.result = *result

	log.SyslogInfo("gpk mpcPointGenerator.calculateResult succeed ",
		"gpk x", hex.EncodeToString(crypto.FromECDSAPub(result)))
	return nil
}
