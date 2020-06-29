package step

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRStep struct {
	BaseMpcStep
	resultKeys []string
	signNum    int

	RShareErrNum    int
	rpkshareOKIndex []uint16
	rpkshareKOIndex []uint16
	rpkshareNOIndex []uint16
	accType         string
}

func CreateMpcRStep(peers *[]mpcprotocol.PeerInfo, accType string) *MpcRStep {
	preValueKeys := []string{mpcprotocol.RPkShare}
	resultkeys := []string{mpcprotocol.RPk}
	signNum := len(preValueKeys)
	mpc := &MpcRStep{*CreateBaseMpcStep(peers, signNum), resultkeys, signNum, 0,
		make([]uint16, 0), make([]uint16, 0), make([]uint16, 0), accType}

	for i := 0; i < signNum; i++ {
		mpc.messages[i] = createPointGenerator(preValueKeys[i])
	}

	return mpc
}

func (addStep *MpcRStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("MpcPointStep.CreateMessage begin")
	message := make([]mpcprotocol.StepMessage, 1)
	message[0].MsgCode = mpcprotocol.MPCMessage
	message[0].PeerID = nil

	pointer := addStep.messages[0].(*mpcPointGenerator)
	//buf.Write(crypto.FromECDSAPub(&pointer.seed))
	seedBytes, err := addStep.schnorrMpcer.MarshPt(pointer.seed)
	if err != nil {
		log.SyslogErr("MpcRStep CreateMessage", "MarshPt err", err.Error())
	}
	h := sha256.Sum256(seedBytes)

	prv, _ := osmconf.GetOsmConf().GetSelfPrvKey()
	r, s, _ := schcomm.SignInternalData(prv, h[:])
	// send rpkshare, sig of rpkshare
	message[0].Data = make([]big.Int, 2)
	message[0].Data[0] = *r
	message[0].Data[1] = *s

	// only one point, rpkShare
	//message[0].BytesData = append(message[0].BytesData, crypto.FromECDSAPub(&pointer.seed))
	message[0].BytesData = append(message[0].BytesData, seedBytes)

	return message
}

func (addStep *MpcRStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	log.SyslogInfo("MpcPointStep.HandleMessage begin ",
		"peerID", msg.PeerID.String(),
		"gpk x", hex.EncodeToString(msg.BytesData[0]))

	pointer := addStep.messages[0].(*mpcPointGenerator)
	_, exist := pointer.message[*msg.PeerID]
	if exist {
		log.SyslogErr("HandleMessage", "MpcPointStep.HandleMessage, get msg from seed fail. peer", msg.PeerID.String())
		return false
	}

	//pointPk := crypto.ToECDSAPub(msg.BytesData[0])
	pointPk, err := addStep.schnorrMpcer.UnMarshPt(msg.BytesData[0])
	if err != nil {
		log.SyslogErr("HandleMessage", "UnMarshPt error ", err.Error())
		return false
	}

	r := msg.Data[0]
	s := msg.Data[1]

	_, grpIdString, _ := osmconf.GetGrpId(addStep.mpcResult)

	senderPk, _ := osmconf.GetOsmConf().GetPKByNodeId(grpIdString, msg.PeerID)

	if !addStep.schnorrMpcer.IsOnCurve(senderPk) {
		log.SyslogErr("MpcPointStep IsOnCurve", "senderPk", addStep.schnorrMpcer.PtToHexString(senderPk))
	}

	senderIndex, _ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString, msg.PeerID)

	var buf bytes.Buffer
	buf.Write(msg.BytesData[0])
	h := sha256.Sum256(buf.Bytes())

	bVerifySig := schcomm.VerifyInternalData(senderPk, h[:], &r, &s)

	if bVerifySig {
		//pointer.message[*msg.PeerID] = *pointPk
		pointer.message[*msg.PeerID] = pointPk

		// save rpkshare for check data of s
		key := mpcprotocol.RPkShare + strconv.Itoa(int(senderIndex))
		addStep.mpcResult.SetByteValue(key, msg.BytesData[0])
		log.SyslogInfo("@@@@@@@@@@@@save rpkshare", "key", key, "rpkshare", hexutil.Encode(msg.BytesData[0]))

		addStep.rpkshareOKIndex = append(addStep.rpkshareOKIndex, uint16(senderIndex))
	} else {
		log.SyslogErr("MpcPointStep::HandleMessage", " check sig fail")
		addStep.rpkshareKOIndex = append(addStep.rpkshareKOIndex, uint16(senderIndex))
	}

	// update no work indexes.

	return true
}

func (addStep *MpcRStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := addStep.BaseMpcStep.FinishStep()
	if err != nil {
		return err
	}

	pointer := addStep.messages[0].(*mpcPointGenerator)

	resultBytes, err := addStep.schnorrMpcer.MarshPt(pointer.result)
	if err != nil {
		log.SyslogErr("MpcRStep FinishStep", "MarshPt error", err.Error())
		return err
	}
	log.Info("generated gpk MpcPointStep::FinishStep",
		"result key", addStep.resultKeys[0],
		"result value ", hexutil.Encode(resultBytes))

	//err = result.SetByteValue(ptStep.resultKeys[0], crypto.FromECDSAPub(&pointer.result))
	err = result.SetByteValue(mpcprotocol.RPk, resultBytes)
	if err != nil {
		log.SyslogErr("HandleMessage", "MpcPointStep.FinishStep, SetValue fail. err", err.Error())
		return err
	}

	log.SyslogInfo("@@@@@@@@@@@@save RPK", "key", mpcprotocol.RPk, "RPK")

	_, grpIdString, _ := osmconf.GetGrpId(addStep.mpcResult)

	allIndex, _ := osmconf.GetOsmConf().GetGrpElemsInxes(grpIdString)
	tempIndex := osmconf.Difference(*allIndex, addStep.rpkshareOKIndex)
	addStep.rpkshareNOIndex = osmconf.Difference(tempIndex, addStep.rpkshareKOIndex)

	log.Info(">>>>>>MpcPointStep", "allIndex", allIndex)
	log.Info(">>>>>>MpcPointStep", "rpkshareOKIndex", addStep.rpkshareOKIndex)
	log.Info(">>>>>>MpcPointStep", "rpkshareKOIndex", addStep.rpkshareKOIndex)
	log.Info(">>>>>>MpcPointStep", "rpkshareNOIndex", addStep.rpkshareNOIndex)

	okIndex := make([]big.Int, len(addStep.rpkshareOKIndex))
	koIndex := make([]big.Int, len(addStep.rpkshareKOIndex))
	noIndex := make([]big.Int, len(addStep.rpkshareNOIndex))

	for i, value := range addStep.rpkshareOKIndex {
		okIndex[i].SetInt64(int64(value))
	}

	for i, value := range addStep.rpkshareKOIndex {
		koIndex[i].SetInt64(int64(value))
	}

	for i, value := range addStep.rpkshareNOIndex {
		noIndex[i].SetInt64(int64(value))
	}

	addStep.mpcResult.SetValue(mpcprotocol.ROKIndex, okIndex)
	addStep.mpcResult.SetValue(mpcprotocol.RKOIndex, koIndex)
	addStep.mpcResult.SetValue(mpcprotocol.RNOIndex, noIndex)

	if err != nil {
		_, retHash := addStep.BaseMpcStep.GetSignedDataHash(result)
		addStep.BaseMpcStep.ShowNotArriveNodes(retHash, mpc.SelfNodeId())
		return err
	}

	return nil
}
