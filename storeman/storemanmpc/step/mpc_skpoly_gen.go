package step

import (
	"crypto/sha256"
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
	randCoefficient []big.Int          //coefficient
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
	grpId,_ := result.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)
	selfIndex, _ := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	key := mpcprotocol.MPCRPolyCoff + strconv.Itoa(int(selfIndex))
	poly.randCoefficient,_ = result.GetValue(key)

	// todo check threshold and len(poly.randCoefficient)
	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	degree := int(threshold) - 1

	// get x = hash(pk)
	for i := 0; i < len(poly.polyValue); i++ {
		nodeId := &(*peers)[i].PeerID
		xValue,_ := osmconf.GetOsmConf().GetXValueByNodeId(grpIdString,nodeId)
		poly.polyValue[i] = schnorrmpc.EvaluatePoly(poly.randCoefficient,
			xValue,
			degree)
		// todo handle error
		h := sha256.Sum256(poly.polyValue[i].Bytes())
		prv,_ := osmconf.GetOsmConf().GetSelfPrvKey()

		poly.polyValueSigR[i], poly.polyValueSigS[i], _ = schnorrmpc.SignInternalData(prv,h[:])
		log.Info("RandomPolynomialGen::initialize poly ",
			"poly peerId", (*peers)[i].PeerID.String(),
			"poly x seed", xValue,
			"sigR", poly.polyValueSigR[i],
			"sigS", poly.polyValueSigS[i])
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
