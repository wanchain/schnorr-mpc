package step

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type mpcSGenerator struct {
	seed        big.Int
	message     map[discover.NodeID]big.Int
	result      big.Int
	preValueKey string
	grpIdString string
	smpcer      mpcprotocol.SchnorrMPCer
}

func createSGenerator(preValueKey string, smpcer mpcprotocol.SchnorrMPCer) *mpcSGenerator {
	return &mpcSGenerator{message: make(map[discover.NodeID]big.Int), preValueKey: preValueKey, smpcer: smpcer}
}

func (msg *mpcSGenerator) initialize(peers *[]mpcprotocol.PeerInfo, result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("mpcSGenerator.initialize begin")

	//	MpcPrivateShare
	//  MpcS

	// rgpk R
	//rgpkValue, err := result.GetValue(mpcprotocol.RPk)
	rgpkBytes, err := result.GetByteValue(mpcprotocol.RPk)

	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get RPk fail")
		return err
	}
	smpcer := msg.smpcer

	//rgpk := *crypto.ToECDSAPub(rgpkBytes)
	//rgpk, err := smpcer.UnMarshPt(rgpkBytes)
	//if err != nil {
	//	log.SyslogErr("mpcSGenerator.initialize UnMarshPt fail", "err", err.Error())
	//	return err
	//}

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
	//buffer.Write(crypto.FromECDSAPub(&rgpk))
	buffer.Write(rgpkBytes)

	mBytes := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mBytes[:])

	rskShare, err := result.GetValue(mpcprotocol.RSkShare)
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get RSkShare fail")
		return err
	}

	gskShare, err := result.GetValue(mpcprotocol.MpcPrivateShare)
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get MpcPrivateShare fail")
		return err
	}
	// malice code begin (just for test)
	// gskShare[0] = *schnorrmpc.BigOne
	// malice code end  (just for test)

	//sigShare := schnorrmpc.SchnorrSign(gskShare[0], rskShare[0], *m)
	sigShare := smpcer.SchnorrSign(gskShare[0], rskShare[0], *m)
	msg.seed = sigShare

	//rpkShare := new(ecdsa.PublicKey)
	//rpkShare.Curve = crypto.S256()
	//rpkShare.X, rpkShare.Y = crypto.S256().ScalarBaseMult(rskShare[0].Bytes())
	//
	//gpkShare := new(ecdsa.PublicKey)
	//gpkShare.Curve = crypto.S256()
	//gpkShare.X, rpkShare.Y = crypto.S256().ScalarBaseMult(gskShare[0].Bytes())

	rpkShare, err := smpcer.SkG(&rskShare[0])
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get MpcPrivateShare fail", "SkG rskShare error", err.Error())
		return err
	}
	gpkShare, err := smpcer.SkG(&gskShare[0])
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get MpcPrivateShare fail", "SkG gskShare error", err.Error())
		return err
	}

	log.Info("@@@@@@@@@@@@@@ SchnorrSign @@@@@@@@@@@@@@",
		"M", hexutil.Encode(MBytes),
		"m", hexutil.Encode(m.Bytes()),
		"gpkShare", smpcer.PtToHexString(gpkShare),
		"rpkShare", smpcer.PtToHexString(rpkShare))

	_, grpIdString, _ := osmconf.GetGrpId(result)

	msg.grpIdString = grpIdString

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
		xValue, err := osmconf.GetOsmConf().GetXValueByNodeId(msg.grpIdString, &nodeId)
		if err != nil {
			log.SyslogErr("mpcSGenerator", "calculateResult.GetXValueByNodeId", err.Error())
		}

		seeds = append(seeds, *xValue)
		// sigshares
		sigshares = append(sigshares, value)
	}

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(msg.grpIdString)
	if threshold < uint16(1) {
		log.SyslogErr("threshold is lesser 1")
		return errors.New("threshold is lesser 1")
	}
	degree := threshold - 1

	// Lagrange
	log.SyslogInfo("all signature share",
		"Need nodes number:", threshold,
		"Now nodes number:", len(sigshares))
	if len(sigshares) < int(threshold) {
		return mpcprotocol.ErrSNW
		//if ok,_ := osmconf.GetOsmConf().IsLeader(msg.grpIdString);ok{
		//	// only leader invoke the errRNW and response to client.
		//	return mpcprotocol.ErrSNW
		//}else{
		//	return nil
		//}

	}

	//result := schnorrmpc.Lagrange(sigshares, seeds[:], int(degree))
	result := msg.smpcer.Lagrange(sigshares, seeds[:], int(degree))
	msg.result = result
	log.SyslogInfo("mpcSGenerator.calculateResult succeed")

	return nil
}

func (msg *mpcSGenerator) SetSchnorrMpcer(smcer mpcprotocol.SchnorrMPCer) error {
	msg.smpcer = smcer
	return nil
}
