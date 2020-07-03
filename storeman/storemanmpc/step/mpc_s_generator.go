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
	rgpkBytes, err := result.GetByteValue(mpcprotocol.RPk)
	if err != nil {
		log.SyslogErr("mpcSGenerator.initialize get RPk fail")
		return err
	}
	smpcer := msg.smpcer

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
	buffer.Write(rgpkBytes)

	mBytes := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mBytes[:])
	m = m.Mod(m, smpcer.GetMod())
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
	sigShare := smpcer.SchnorrSign(gskShare[0], rskShare[0], *m)
	msg.seed = sigShare

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

	log.Info("@@@@@@ SchnorrSign @@@@@@",
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
		xValue, err := osmconf.GetOsmConf().GetXValueByNodeId(msg.grpIdString, &nodeId, msg.smpcer)
		if err != nil {
			log.SyslogErr("mpcSGenerator", "calculateResult.GetXValueByNodeId", err.Error())
		}

		seeds = append(seeds, *xValue)
		sigshares = append(sigshares, value)
	}

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(msg.grpIdString)
	if threshold < uint16(1) {
		log.SyslogErr("threshold is lesser 1")
		return errors.New("threshold is lesser 1")
	}
	degree := threshold - 1

	log.SyslogInfo("all signature share",
		"Need nodes number:", threshold,
		"Now nodes number:", len(sigshares))
	if len(sigshares) < int(threshold) {
		return mpcprotocol.ErrSNW
	}

	result := msg.smpcer.Lagrange(sigshares, seeds[:], int(degree))
	msg.result = result
	log.SyslogInfo("mpcSGenerator.calculateResult succeed")

	return nil
}

func (msg *mpcSGenerator) SetSchnorrMpcer(smcer mpcprotocol.SchnorrMPCer) error {
	msg.smpcer = smcer
	return nil
}
