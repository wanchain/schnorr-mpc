package step

import (
	"encoding/hex"
	"errors"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type mpcPointGenerator struct {
	//seed        ecdsa.PublicKey
	//message     map[discover.NodeID]ecdsa.PublicKey
	//result      ecdsa.PublicKey
	//preValueKey string
	//grpIdString string
	//smcer       mpcprotocol.SchnorrMPCer

	seed        mpcprotocol.CurvePointer
	message     map[discover.NodeID]mpcprotocol.CurvePointer
	result      mpcprotocol.CurvePointer
	preValueKey string
	grpIdString string
	smcer       mpcprotocol.SchnorrMPCer
}

func createPointGenerator(preValueKey string) *mpcPointGenerator {
	return &mpcPointGenerator{message: make(map[discover.NodeID]mpcprotocol.CurvePointer), preValueKey: preValueKey}
}

func (point *mpcPointGenerator) initialize(peers *[]mpcprotocol.PeerInfo, result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("mpcPointGenerator.initialize begin ")

	// get self rpkshare
	_, grpIdString, _ := osmconf.GetGrpId(result)

	point.grpIdString = grpIdString

	selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	if err != nil {
		log.SyslogErr("mpcPointGenerator", "initialize", err)
		return err
	}
	key := mpcprotocol.RPkShare + strconv.Itoa(int(selfIndex))
	value, err := result.GetByteValue(key)

	log.SyslogInfo("public share mpcPointGenerator.initialize GetValue ",
		"key", point.preValueKey,
		"pk share ", hex.EncodeToString(value))

	if err != nil {
		log.SyslogErr("mpcPointGenerator.initialize get preValueKey fail")
		return err
	}

	//point.seed = *crypto.ToECDSAPub(value)
	point.seed, err = point.smcer.UnMarshPt(value)
	if err != nil {
		log.SyslogErr("mpcPointGenerator", "UnMarshPt", err.Error())
		return err
	}

	log.SyslogInfo("mpcPointGenerator.initialize succeed")
	return nil
}

func (point *mpcPointGenerator) calculateResult() error {
	log.SyslogInfo("mpcPointGenerator.calculateResult begin")

	seeds := make([]big.Int, 0)
	//gpkshares := make([]ecdsa.PublicKey, 0)
	gpkshares := make([]mpcprotocol.CurvePointer, 0)
	for nodeId, value := range point.message {

		xValue, err := osmconf.GetOsmConf().GetXValueByNodeId(point.grpIdString, &nodeId)
		xValue.Mod(xValue, point.smcer.GetMod())

		if err != nil {
			log.SyslogErr("mpcPointGenerator", "calculateResult", err.Error())
			return err
		}
		seeds = append(seeds, *xValue)

		// build PK[]
		//var gpkshare ecdsa.PublicKey
		//gpkshare.Curve = crypto.S256()
		//
		//gpkshare.X = value.X
		//gpkshare.Y = value.Y
		//
		//gpkshares = append(gpkshares, gpkshare)

		gpkshares = append(gpkshares, value)

	}

	for index, gpkshareTemp := range gpkshares {
		log.SyslogInfo("all public share",
			"gpk share ", point.smcer.PtToHexString(gpkshareTemp),
			"seed", hex.EncodeToString(seeds[index].Bytes()))
	}

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(point.grpIdString)
	if threshold < uint16(1) {
		log.SyslogErr("threshold is lesser 1")
		return errors.New("threshold is lesser 1")
	}
	degree := threshold - 1
	// lagrangeEcc
	log.SyslogInfo("all public",
		"Need nodes number:", threshold,
		"Now nodes number:", len(gpkshares))
	if len(gpkshares) < int(threshold) {
		return mpcprotocol.ErrRNW
	}

	smpcer := point.smcer
	//result := schnorrmpc.LagrangeECC(gpkshares, seeds[:], int(degree))
	//
	//if !schnorrmpc.ValidatePublicKey(result) {
	//	log.SyslogErr("mpcPointGenerator::calculateResult", "mpcPointGenerator.ValidatePublicKey fail. err", mpcprotocol.ErrPointZero.Error())
	//	return mpcprotocol.ErrPointZero
	//}

	result := smpcer.LagrangeECC(gpkshares, seeds[:], int(degree))

	//if !schnorrmpc.ValidatePublicKey(result) {
	//	log.SyslogErr("mpcPointGenerator::calculateResult", "mpcPointGenerator.ValidatePublicKey fail. err", mpcprotocol.ErrPointZero.Error())
	//	return mpcprotocol.ErrPointZero
	//}

	if !smpcer.IsOnCurve(result) {
		log.SyslogErr("mpcPointGenerator::calculateResult", "mpcPointGenerator.ValidatePublicKey fail. err", mpcprotocol.ErrPointZero.Error())
		return mpcprotocol.ErrPointZero
	}

	point.result = result

	log.SyslogInfo("gpk mpcPointGenerator.calculateResult succeed ",
		"gpk ", smpcer.PtToHexString(result))
	return nil
}

func (point *mpcPointGenerator) SetSchnorrMpcer(smcer mpcprotocol.SchnorrMPCer) error {
	point.smcer = smcer
	return nil
}
