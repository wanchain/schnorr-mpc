package step

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type RandomPolynomialGen struct {
	randCoefficient []big.Int                   //coefficient
	message         map[discover.NodeID]big.Int //Polynomial result
	polyValue       []big.Int
	polyValueSigR   []*big.Int
	polyValueSigS   []*big.Int
	result          *big.Int
}

func createSkPolyGen(degree int, peerNum int) *RandomPolynomialGen {
	return &RandomPolynomialGen{make([]big.Int, degree+1),
		make(map[discover.NodeID]big.Int),
		make([]big.Int, peerNum),
		make([]*big.Int, peerNum),
		make([]*big.Int, peerNum),
		nil}
}

func (poly *RandomPolynomialGen) initialize(peers *[]mpcprotocol.PeerInfo,
	result mpcprotocol.MpcResultInterface) error {

	log.Info("RandomPolynomialGen::initialize ", "len of recieved message", len(poly.message))

	// get randCoefficient
	_, grpIdString, _ := osmconf.GetGrpId(result)

	selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	if err != nil {
		log.SyslogErr("RandomPolynomialGen", "initialize", err.Error())
	}
	key := mpcprotocol.RPolyCoff + strconv.Itoa(int(selfIndex))
	poly.randCoefficient, _ = result.GetValue(key)

	// check threshold and len(poly.randCoefficient)
	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	if threshold < 1 || int(threshold) != len(poly.randCoefficient) {
		err := errors.New(fmt.Sprintf("RandomPolynomialGen initialize GetThresholdNum threshold = %v", threshold))
		log.SyslogErr(err.Error())
		return err
	}
	degree := int(threshold) - 1

	// get x = hash(pk)
	for i := 0; i < len(poly.polyValue); i++ {
		nodeId := &(*peers)[i].PeerID
		xValue, err := osmconf.GetOsmConf().GetXValueByNodeId(grpIdString, nodeId)
		if err != nil {
			log.SyslogErr("RandomPolynomialGen", "initialize.GetXValueByNodeId", err.Error())
		}
		rcvIndex, _ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString, nodeId)

		log.Info("============RandomPolynomialGen::initialize poly ",
			"len(poly.randCoefficient)", len(poly.randCoefficient),
			"poly x seed", xValue,
			"degree", degree)

		poly.polyValue[i] = schnorrmpc.EvaluatePoly(poly.randCoefficient,
			xValue,
			degree)

		h := sha256.Sum256(poly.polyValue[i].Bytes())
		prv, err := osmconf.GetOsmConf().GetSelfPrvKey()
		if err != nil {
			log.SyslogErr("RandomPolynomialGen::initialize", "GetSelfPrvKey error", err.Error())
			return err
		}

		poly.polyValueSigR[i], poly.polyValueSigS[i], _ = schnorrmpc.SignInternalData(prv, h[:])
		log.Info("RandomPolynomialGen::initialize poly ",
			"group id", grpIdString,
			"senderPk", hexutil.Encode(crypto.FromECDSAPub(&prv.PublicKey)),
			"senderIndex", selfIndex,
			"rcvIndex", rcvIndex,
			"poly peerId", (*peers)[i].PeerID.String(),
			"poly x seed", xValue,
			"sigR", hexutil.Encode(poly.polyValueSigR[i].Bytes()),
			"sigS", hexutil.Encode(poly.polyValueSigS[i].Bytes()),
			"h", hexutil.Encode(h[:]))
	}

	return nil
}

func (poly *RandomPolynomialGen) calculateResult() error {
	poly.result = big.NewInt(0)
	log.Info("RandomPolynomialGen::calculateResult ", "len of recieved message", len(poly.message))
	for _, value := range poly.message {
		poly.result.Add(poly.result, &value)
		poly.result.Mod(poly.result, crypto.S256().Params().N)
	}

	return nil
}
