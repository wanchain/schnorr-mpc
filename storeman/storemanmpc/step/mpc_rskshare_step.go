package step

import (
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRSKShare_Step struct {
	BaseMpcStep
	RSkErrNum uint16
}

func CreateMpcRSKShareStep(degree int, peers *[]mpcprotocol.PeerInfo) *MpcRSKShare_Step {
	mpc := &MpcRSKShare_Step{*CreateBaseMpcStep(peers, 1), 0}
	mpc.messages[0] = createSkPolyGen(degree, len(*peers), mpc.schnorrMpcer)
	return mpc
}

func (rss *MpcRSKShare_Step) CreateMessage() []mpcprotocol.StepMessage {
	// data: bigInt + R(bigInt) + S(bigInt)
	message := make([]mpcprotocol.StepMessage, len(*rss.peers))
	skpv := rss.messages[0].(*RandomPolynomialGen)
	for i := 0; i < len(*rss.peers); i++ {
		message[i].MsgCode = mpcprotocol.MPCMessage
		message[i].PeerID = &(*rss.peers)[i].PeerID
		message[i].Data = make([]big.Int, 3)

		if schcomm.MaliceRContent {
			message[i].Data[0] = *schcomm.BigOne
		} else {
			message[i].Data[0] = skpv.polyValue[i]
		}

		message[i].Data[1] = *skpv.polyValueSigR[i]
		if schcomm.MaliceRSig {
			message[i].Data[2] = *schcomm.BigOne // used to simulate R stage malice
		} else {
			message[i].Data[2] = *skpv.polyValueSigS[i]
		}

	}

	return message
}

func (rss *MpcRSKShare_Step) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := rss.BaseMpcStep.FinishStep()
	if err != nil {
		return err
	}

	// rskShare
	skpv := rss.messages[0].(*RandomPolynomialGen)
	err = result.SetValue(mpcprotocol.RSkShare, []big.Int{*skpv.result})
	if err != nil {
		return err
	}
	// rpkShare
	rpkShare, err := rss.schnorrMpcer.SkG(skpv.result)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "SkG err", err.Error())
	}

	// RPkShare + selfIndex
	_, grpIdString, _ := osmconf.GetGrpId(rss.mpcResult)

	selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "FinishStep", err.Error())
		return err
	}
	key := mpcprotocol.RPkShare + strconv.Itoa(int(selfIndex))

	//err = result.SetByteValue(key, crypto.FromECDSAPub(rpkShare))
	rpkShareBytes, err := rss.schnorrMpcer.MarshPt(rpkShare)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "MarshPt", err.Error())
		return err
	}
	err = result.SetByteValue(key, rpkShareBytes)
	if err != nil {
		return err
	}

	rpkShareTemp, err := rss.schnorrMpcer.UnMarshPt(rpkShareBytes)
	if err != nil {
		log.SyslogDebug("rss.schnorrMpcer.UnMarshPt", "error", err.Error())
	}
	if rss.schnorrMpcer.IsOnCurve(rpkShareTemp) {
		log.SyslogDebug("rss.schnorrMpcer.IsOnCurve", "rpkShareBytes", hexutil.Encode(rpkShareBytes))
	} else {
		log.SyslogDebug("rss.schnorrMpcer.IsOnCurve Not on Curve", "rpkShareBytes", hexutil.Encode(rpkShareBytes))
	}

	log.SyslogInfo("@@@@@@@@@@@@@@@@@@@MpcRSKShare_Step",
		"rpkShare", hexutil.Encode(rpkShareBytes),
		"rskShare", hexutil.Encode((*skpv.result).Bytes()))

	rcvCollection, err := rss.buildRcvedCollection()
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "buildRcvedCollection err", err.Error())
		return err
	}

	err = rss.wrRcvedCollection(rcvCollection)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "wrRcvedCollection err", err.Error())
		return err
	}
	log.SyslogInfo("@@@@@@@@@@@@@@@@@@@MpcRSKShare_Step save RcvedCollection",
		" rcvCollection", hexutil.Encode(rcvCollection.Bytes()))

	err = rss.wrSkSIJ()
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", " wrSkShare err", err.Error())
		return err
	}

	return nil
}

func (rss *MpcRSKShare_Step) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	_, grpIdString, _ := osmconf.GetGrpId(rss.mpcResult)

	senderPk, _ := osmconf.GetOsmConf().GetPKByNodeId(grpIdString, msg.PeerID)
	err := schcomm.CheckPK(senderPk)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", " HandleMessage", err.Error())
	}

	senderIndex, _ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString, msg.PeerID)
	selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", " HandleMessage.GetSelfInx", err.Error())
	}

	// get data, r, s
	sij := msg.Data[0]
	r := msg.Data[1]
	s := msg.Data[2]

	// 1. check sig
	h := sha256.Sum256(sij.Bytes())
	bVerifySig := schcomm.VerifyInternalData(senderPk, h[:], &r, &s)

	bContent := true

	if schcomm.MaliceRSigRcv && bVerifySig {
		bVerifySig = false
	}

	if !bVerifySig {
		log.SyslogErr("MpcRSKShare_Step::HandleMessage:VerifyInternalData",
			" verify sk sig fail", msg.PeerID.String(),
			"groupId", grpIdString,
			"senderPK", hexutil.Encode(crypto.FromECDSAPub(senderPk)),
			"senderIndex", senderIndex,
			"recieverIndex", selfIndex,
			"R", hexutil.Encode(r.Bytes()),
			"S", hexutil.Encode(s.Bytes()),
			"h[:]", hexutil.Encode(h[:]))
	} else {
		log.SyslogDebug("MpcRSKShare_Step::HandleMessage:VerifyInternalData",
			" verify sk sig successfully", msg.PeerID.String(),
			"groupId", grpIdString,
			"senderPK", hexutil.Encode(crypto.FromECDSAPub(senderPk)),
			"senderIndex", senderIndex,
			"recieverIndex", selfIndex,
			"R", hexutil.Encode(r.Bytes()),
			"S", hexutil.Encode(s.Bytes()),
			"h[:]", hexutil.Encode(h[:]))
	}

	// 2. check sij*G=si+a[i][0]*X+a[i][1]*X^2+...+a[i][n]*x^(n-1)
	selfNodeId, _ := osmconf.GetOsmConf().GetSelfNodeId()
	xValue, err := osmconf.GetOsmConf().GetXValueByNodeId(grpIdString, selfNodeId, rss.schnorrMpcer)
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "GetXValueByNodeId", err.Error())
	}

	// get sender poly commit
	keyPolyCMG := mpcprotocol.RPolyCMG + strconv.Itoa(int(senderIndex))
	pgBytes, _ := rss.mpcResult.GetByteValue(keyPolyCMG)

	pks, err := rss.schnorrMpcer.SplitPksFromBytes(pgBytes[:])
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step::HandleMessage",
			" polyCMG GetBytevalue error", err.Error())

		bContent = false
	}

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	if threshold < 1 {
		log.SyslogErr("before evalByPolyG threshold should be greater 1", "threshold", threshold)
		return true
	}
	if len(pks) != int(threshold) {
		log.SyslogErr("before evalByPolyG", "len(pks)", len(pks), "threshold", threshold)
		return true
	}
	sijgEval, err := rss.schnorrMpcer.EvalByPolyG(pks, uint16(len(pks)-1), xValue)
	if err != nil {
		log.SyslogErr("schnorrmpc.EvalByPolyG", "error", err.Error())
		return true
	}

	sijg, _ := rss.schnorrMpcer.SkG(&sij)
	if !rss.schnorrMpcer.Equal(sijg, sijgEval) {
		bContent = false
	}

	if schcomm.MaliceRContentRcv && bContent {
		bContent = false
	}

	if !bContent || !bVerifySig {
		// check Not success
		log.SyslogErr("MpcRSKShare_Step::HandleMessage",
			" verify sk data fail", msg.PeerID.String(),
			"groupId", grpIdString)

		rss.RSkErrNum += 1

		//error s[i][j]
		log.SyslogInfo("RSkErr Info", "ErrNum", rss.RSkErrNum)
		if rss.RSkErrNum >= 1 {
			rskErrInfo := make([]big.Int, 5)
			// sendIndex, rvcIndex, s[i][j], r, s
			rskErrInfo[0] = *big.NewInt(0).SetInt64(int64(senderIndex))
			rskErrInfo[1] = *big.NewInt(0).SetInt64(int64(selfIndex))
			rskErrInfo[2] = sij
			rskErrInfo[3] = r
			rskErrInfo[4] = s

			keyErrInfo := mpcprotocol.RSkErrInfos + strconv.Itoa(int(rss.RSkErrNum)-1)
			log.SyslogErr("RSkErr Info", "key", keyErrInfo, "error info", rskErrInfo)
			err := rss.mpcResult.SetValue(keyErrInfo, rskErrInfo)
			if err != nil {
				log.SyslogErr("RSkErr Info SetValue Failed", "key", keyErrInfo, "error", err.Error())
			} else {
				log.SyslogErr("RSkErr Info SetValue success", "key", keyErrInfo)
			}
		}
	}

	keyErrNum := mpcprotocol.RSkErrNum
	rskErrInfoNum := make([]big.Int, 1)
	rskErrInfoNum[0] = *big.NewInt(0).SetInt64(int64(rss.RSkErrNum))
	rss.mpcResult.SetValue(keyErrNum, rskErrInfoNum)

	skpv := rss.messages[0].(*RandomPolynomialGen)
	_, exist := skpv.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcRSKShare_Step::HandleMessage", " can't find msg . peerID",
			msg.PeerID.String(), " PeerID", *msg.PeerID)
		return false
	}

	skpv.message[*msg.PeerID] = msg.Data[0] //message.Value
	return true
}

func (rss *MpcRSKShare_Step) buildRcvedCollection() (*big.Int, error) {
	skpv := rss.messages[0].(*RandomPolynomialGen)
	_, grpIdString, _ := osmconf.GetGrpId(rss.mpcResult)

	bigs := make([]big.Int, 0)
	for peerId, _ := range skpv.message {
		senderIndex, _ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString, &peerId)
		bigs = append(bigs, *big.NewInt(0).SetUint64(uint64(senderIndex)))
	}
	return osmconf.BuildDataByIndexes(&bigs)
}

func (rss *MpcRSKShare_Step) wrRcvedCollection(rcvCol *big.Int) error {

	err := rss.mpcResult.SetValue(mpcprotocol.RRcvedColl, []big.Int{*rcvCol})
	if err != nil {
		log.SyslogErr("MpcRSKShare_Step", "wrRcvedCollection error ", err.Error())
		return err
	}
	return nil
}

func (rss *MpcRSKShare_Step) wrSkSIJ() error {
	skpv := rss.messages[0].(*RandomPolynomialGen)
	_, grpIdString, _ := osmconf.GetGrpId(rss.mpcResult)

	for peerId, sij := range skpv.message {
		senderIndex, _ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString, &peerId)
		key := mpcprotocol.RSKSIJ + strconv.Itoa(int(senderIndex))
		err := rss.mpcResult.SetValue(key, []big.Int{sij})
		if err != nil {
			log.SyslogErr("\t\t\tMpcRSKShare_Step", "wrSkSIJ error ", err.Error())
			return err
		}
		log.SyslogInfo("\t\t\tMpcRSKShare_Step wrSkSIJ", "key", key, "value", hexutil.Encode(sij.Bytes()))
	}

	return nil
}
