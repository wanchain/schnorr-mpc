package step

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type mpcSGenerator struct {
	seed        big.Int
	message     map[discover.NodeID]big.Int
	result      big.Int
	preValueKey string
	grpIdString	string
}

func createSGenerator(preValueKey string) *mpcSGenerator {
	return &mpcSGenerator{message: make(map[discover.NodeID]big.Int), preValueKey: preValueKey}
}

func (msg *mpcSGenerator) initialize(peers *[]mpcprotocol.PeerInfo, result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("mpcSGenerator.initialize begin")

	// rgpk R
	rgpkValue, err := result.GetValue(mpcprotocol.RPublicKeyResult)

	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get RPublicKeyResult fail")
		return err
	}

	var rgpk ecdsa.PublicKey
	rgpk.Curve = crypto.S256()
	rgpk.X, rgpk.Y = &rgpkValue[0], &rgpkValue[1]

	// M
	MBytes, err := result.GetByteValue(mpcprotocol.MpcM)
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get MpcM fail")
		return err
	}

	hashMBytes := sha256.Sum256(MBytes)

	// compute m
	var buffer bytes.Buffer
	buffer.Write(hashMBytes[:])
	buffer.Write(crypto.FromECDSAPub(&rgpk))

	mBytes := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mBytes[:])

	rskShare, err := result.GetValue(mpcprotocol.RMpcPrivateShare)
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get RMpcPrivateShare fail")
		return err
	}

	gskShare, err := result.GetValue(mpcprotocol.MpcPrivateShare)
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get MpcPrivateShare fail")
		return err
	}
	sigShare := schnorrmpc.SchnorrSign(gskShare[0], rskShare[0], *m)
	msg.seed = sigShare

	log.Info("@@@@@@@@@@@@@@ SchnorrSign @@@@@@@@@@@@@@",
		"M", hex.EncodeToString(MBytes),
		"m", hex.EncodeToString(m.Bytes()))

	grpId,_ := result.GetByteValue(mpcprotocol.MpcGrpId)
	msg.grpIdString = string(grpId)

	log.SyslogInfo("mpcSGenerator.initialize succeed")
	return nil
}

func (msg *mpcSGenerator) calculateResult() error {
	log.SyslogInfo("mpcSGenerator.calculateResult begin")
	// x
	seeds := make([]big.Int, 0)
	sigshares := make([]big.Int, 0)
	for nodeId, value := range msg.message {
		// get seeds, need sort seeds, and make seeds as a key of map, and check the map's count??
		xValue,_ := osmconf.GetOsmConf().GetXValueByNodeId(msg.grpIdString,&nodeId)
		seeds = append(seeds, *xValue)
		// sigshares
		sigshares = append(sigshares, value)
	}

	// Lagrange
	log.SyslogInfo("all signature share",
		"Need nodes number:", mpcprotocol.MpcSchnrThr,
		"Now nodes number:", len(sigshares))
	if len(sigshares) < mpcprotocol.MpcSchnrThr {
		return mpcprotocol.ErrTooLessDataCollected
	}
	result := schnorrmpc.Lagrange(sigshares, seeds[:], mpcprotocol.MPCDegree)
	msg.result = result
	log.SyslogInfo("mpcSGenerator.calculateResult succeed")

	return nil
}
