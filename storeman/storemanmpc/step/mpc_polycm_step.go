package step

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

const (
	MpcPolycmStepMsgDataNumber = 2
)

type MpcPolycmStep struct {
	BaseStep
	message        map[discover.NodeID]bool
	polycmGMap     mpcprotocol.PolyGMap
	polycmGMSigMap mpcprotocol.PolyGSigMap
	polyCoff       mpcprotocol.Polynomial
	selfIndex      uint16
	grpId          string
}

func CreateMpcPolycmStep(peers *[]mpcprotocol.PeerInfo) *MpcPolycmStep {

	return &MpcPolycmStep{
		BaseStep:       *CreateBaseStep(peers, len(*peers)-1),
		message:        make(map[discover.NodeID]bool),
		polycmGMap:     make(mpcprotocol.PolyGMap),
		polycmGMSigMap: make(mpcprotocol.PolyGSigMap),
		polyCoff:       nil}
}

func (req *MpcPolycmStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("MpcPolycm Step.InitStep begin")
	req.BaseStep.InitStep(result)
	// build self polynomial

	_, grpIdString, _ := osmconf.GetGrpId(req.mpcResult)

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	degree := threshold - 1
	smpcer := req.schnorrMpcer
	s, err := rand.Int(rand.Reader, smpcer.GetMod())
	if err != nil {
		log.SyslogErr("MpcPolycmStep::InitStep", "rand.Int fail. err", err.Error())
		return err
	}

	cof := smpcer.RandPoly(int(degree), *s)

	req.polyCoff = make(mpcprotocol.Polynomial, len(cof))
	copy(req.polyCoff, cof)

	log.SyslogInfo("MpcPolycmStep:InitStep", "len(req.polyCoff)", len(req.polyCoff), "len(cof)", len(cof))

	// build polycmG
	pg := make(mpcprotocol.PolynomialG, threshold)
	for index, value := range cof {
		skG, _ := smpcer.SkG(&value)
		pg[index] = skG
	}
	req.grpId = grpIdString
	selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	if err != nil {
		log.SyslogErr("MpcPolycmStep:InitStep", "GetSelfInx", err.Error())
		return err
	}
	req.selfIndex = selfIndex

	req.polycmGMap[selfIndex] = pg

	for key, value := range req.polycmGMap {
		log.SyslogDebug("-----------------key", "key index", key)
		for index, pk := range value {
			log.SyslogDebug("-----------------G", "index", index, "G", smpcer.PtToHexString(pk))
		}
	}
	return nil
}

func (req *MpcPolycmStep) CreateMessage() []mpcprotocol.StepMessage {
	// broadcast self polynomialG
	// grpId + threshold G + R + S
	log.Info("MpcPolycmStep.CreateMessage.....")
	log.Info("MpcPolycmStep", "CreateMessage peers", *req.peers)
	msg := mpcprotocol.StepMessage{
		MsgCode:   mpcprotocol.MPCMessage,
		PeerID:    nil,
		Peers:     nil,
		Data:      nil,
		BytesData: nil}

	_, grpIdString, _ := osmconf.GetGrpId(req.mpcResult)

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	// Data[0]: R
	// Data[1]: S
	smpcer := req.schnorrMpcer
	// BytesData[i]: the ith poly commit G
	msg.BytesData = make([][]byte, threshold)

	for i := 0; i < int(threshold); i++ {
		msg.BytesData[i] = make([]byte, smpcer.PtByteLen())
	}
	// build msg.data & msg.bytedata
	var buf bytes.Buffer
	for index, pk := range req.polycmGMap[req.selfIndex] {

		ptBytes, err := smpcer.MarshPt(pk)
		if err != nil {
			log.SyslogErr("MpcPolycmStep", "CreateMessage err", err.Error())
		}
		buf.Write(ptBytes)
		msg.BytesData[index] = ptBytes
	}

	//prv,_ := osmconf.GetOsmConf().GetSelfPrvKey()
	h := sha256.Sum256(buf.Bytes())
	prv, _ := osmconf.GetOsmConf().GetSelfPrvKey()
	r, s, _ := schcomm.SignInternalData(prv, h[:])

	msg.Data = make([]big.Int, 2)
	msg.Data[0] = *r
	msg.Data[1] = *s

	req.polycmGMSigMap[req.selfIndex] = make([]big.Int, 2)
	req.polycmGMSigMap[req.selfIndex][0] = *r
	req.polycmGMSigMap[req.selfIndex][0] = *s

	return []mpcprotocol.StepMessage{msg}
}

func (req *MpcPolycmStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := req.BaseStep.FinishStep()
	if err != nil {
		return err
	}
	smpcer := req.schnorrMpcer
	// save other poly commit to the mpc context, bytevalue: cmg
	for index, polyCms := range req.polycmGMap {
		key := mpcprotocol.RPolyCMG + strconv.Itoa(int(index))
		var buf bytes.Buffer
		for _, polyCmItem := range polyCms {
			ptBytes, err := smpcer.MarshPt(polyCmItem)
			if err != nil {
				return err
			}
			buf.Write(ptBytes)
		}
		result.SetByteValue(key, buf.Bytes())

		log.SyslogInfo("Save polyCmG", "index", index, "key", key,
			"poly commits", hex.EncodeToString(buf.Bytes()))
	}

	// save other poly commit sig to the mpc context, value: sig
	for index, polyCmsSig := range req.polycmGMSigMap {
		key := mpcprotocol.RPolyCMG + strconv.Itoa(int(index))

		bigs := make([]big.Int, 2)
		bigs[0] = polyCmsSig[0]
		bigs[1] = polyCmsSig[1]
		result.SetValue(key, bigs)

		log.SyslogInfo("Save polyCmsSig", "index", index, "key", key,
			"R", hex.EncodeToString(bigs[0].Bytes()),
			"S", hex.EncodeToString(bigs[1].Bytes()))
	}

	// save self poly commit coff to the mpc context
	key := mpcprotocol.RPolyCoff + strconv.Itoa(int(req.selfIndex))

	coff := make([]big.Int, 0)
	for _, polyCmCoffItem := range req.polyCoff {
		coff = append(coff, polyCmCoffItem)
	}

	log.SyslogInfo("======MpcPolycmStep:FinishStep save coff ", "len(coff)", len(coff))

	result.SetValue(key, coff[:])
	return nil
}

func (req *MpcPolycmStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	// save others polynomial
	log.SyslogInfo("MpcPolycmStep::HandleMessage", "MpcPolycmStep.HandleMessage begin, peerID", msg.PeerID.String())
	_, exist := req.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcPolycmStep::HandleMessage", "MpcPolycmStep.HandleMessage, get message from peerID fail. peer",
			msg.PeerID.String())
		return false
	}

	req.message[*msg.PeerID] = true

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(req.grpId)

	// check poly coff count
	if len(msg.BytesData) != int(threshold) {
		log.SyslogInfo("MpcPolycmStep::HandleMessage",
			"peerId", msg.PeerID.String(),
			"threshold", threshold,
			"len(msg.BytesData)", len(msg.BytesData),
			"len(msg.Data)", len(msg.Data))

		return false
	}
	// check count for  bigInt of sig
	if len(msg.Data) != MpcPolycmStepMsgDataNumber {
		log.SyslogInfo("MpcPolycmStep::HandleMessage",
			"peerId", msg.PeerID.String(),
			"threshold", threshold,
			"len(msg.BytesData)", len(msg.BytesData),
			"len(msg.Data)", len(msg.Data))

		return false
	}
	if !req.checkSig(msg) {
		return false
	}
	req.fillCmIntoMap(msg)
	return true
}

func (req *MpcPolycmStep) checkSig(msg *mpcprotocol.StepMessage) bool {
	r := &msg.Data[0]
	s := &msg.Data[1]

	var buf bytes.Buffer
	for _, pkBytes := range msg.BytesData {
		buf.Write(pkBytes)
	}
	h := sha256.Sum256(buf.Bytes())

	_, grpId, err := osmconf.GetGrpId(req.mpcResult)
	if err != nil {
		log.SyslogErr("MpcPolycmStep", "checkSig err", err.Error())
		return false
	}

	senderPk, err := osmconf.GetOsmConf().GetPKByNodeId(grpId, msg.PeerID)
	if err != nil {
		log.SyslogErr("MpcPolycmStep", "checkSig GetPKByNodeId err", err.Error())
		return false
	}
	return schcomm.VerifyInternalData(senderPk, h[:], r, s)

}

func (req *MpcPolycmStep) fillCmIntoMap(msg *mpcprotocol.StepMessage) bool {
	nodeId := msg.PeerID

	inx, _ := osmconf.GetOsmConf().GetInxByNodeId(req.grpId, nodeId)

	_, grpIdString, _ := osmconf.GetGrpId(req.mpcResult)

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	// build polycmG
	pg := make(mpcprotocol.PolynomialG, threshold)

	smpcer := req.schnorrMpcer
	log.SyslogDebug("fillCmIntoMap", "map key", inx, "group", grpIdString, "threshold", threshold, "len(msg.BytesData)", len(msg.BytesData))
	for i := 0; i < len(msg.BytesData); i++ {
		log.SyslogDebug("		fillCmIntoMap", "item index", i, "From message one poly commit item G", hexutil.Encode(msg.BytesData[i][:]))
		pt, err := smpcer.UnMarshPt(msg.BytesData[i][:])
		if err != nil {
			return false
		}
		pg[i] = pt
	}
	req.polycmGMap[inx] = pg

	req.polycmGMSigMap[inx] = append(req.polycmGMSigMap[inx], msg.Data[0])
	req.polycmGMSigMap[inx] = append(req.polycmGMSigMap[inx], msg.Data[1])

	return true
}
