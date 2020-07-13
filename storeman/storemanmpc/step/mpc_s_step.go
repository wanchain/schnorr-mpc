package step

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcSStep struct {
	BaseMpcStep
	resultKeys   []string
	signNum      int
	SShareErrNum int

	sshareOKIndex []uint16
	sshareKOIndex []uint16
	sshareNOIndex []uint16
}

func CreateMpcSStep(peers *[]mpcprotocol.PeerInfo, preValueKeys []string, resultKeys []string) *MpcSStep {

	log.SyslogInfo("CreateMpcSStep begin")
	signNum := len(preValueKeys)
	mpc := &MpcSStep{*CreateBaseMpcStep(peers, signNum), resultKeys, signNum, 0,
		make([]uint16, 0), make([]uint16, 0), make([]uint16, 0)}

	for i := 0; i < signNum; i++ {
		mpc.messages[i] = createSGenerator(preValueKeys[i], mpc.schnorrMpcer)
	}

	return mpc
}

func (msStep *MpcSStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("MpcSStep.CreateMessage begin")
	// sshare, sig of sshare

	message := make([]mpcprotocol.StepMessage, 1)
	message[0].MsgCode = mpcprotocol.MPCMessage
	message[0].PeerID = nil

	for i := 0; i < msStep.signNum; i++ {
		pointer := msStep.messages[i].(*mpcSGenerator)

		h := sha256.Sum256(pointer.seed.Bytes())
		prv, _ := osmconf.GetOsmConf().GetSelfPrvKey()
		r, s, _ := schcomm.SignInternalData(prv, h[:])

		message[i].Data = make([]big.Int, 3)

		if schcomm.MaliceSSig {
			message[i].Data[0] = *schcomm.BigOne
		} else {
			message[i].Data[0] = pointer.seed
		}

		message[i].Data[1] = *r

		if schcomm.MaliceSContent {
			message[i].Data[2] = *schcomm.BigOne
		} else {
			message[i].Data[2] = *s
		}
	}

	return message
}

func (msStep *MpcSStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("MpcSStep::HandleMessage", "MpcSStep.HandleMessage begin, peerID", msg.PeerID.String())

	for i := 0; i < msStep.signNum; i++ {
		pointer := msStep.messages[i].(*mpcSGenerator)
		_, exist := pointer.message[*msg.PeerID]
		if exist {
			log.SyslogErr("MpcSStep::HandleMessage", "MpcSStep.HandleMessage, get msg from seed fail. peer", msg.PeerID.String())
			return false
		}

		sshare := msg.Data[3*i]
		r := msg.Data[3*i+1]
		s := msg.Data[3*i+2]

		_, grpIdString, _ := osmconf.GetGrpId(msStep.mpcResult)

		senderPk, _ := osmconf.GetOsmConf().GetPKByNodeId(grpIdString, msg.PeerID)

		err := schcomm.CheckPK(senderPk)
		if err != nil {
			log.SyslogErr("MpcSStep", "HandleMessage", err.Error())
		}

		senderIndex, _ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString, msg.PeerID)

		// 1. check sig
		h := sha256.Sum256(sshare.Bytes())
		bVerifySig := schcomm.VerifyInternalData(senderPk, h[:], &r, &s)

		if !bVerifySig {
			// save error and send judge info to leader
			log.SyslogErr("MpcPointStep::HandleMessage", " check sig fail")

		} else {
			log.SyslogInfo("check sig of sshare successfully", " senderIndex", senderIndex)
		}

		// 2. check content
		selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
		if err != nil {
			log.SyslogInfo("MpcSStep", " GetSelfInx", err.Error())
		}

		log.SyslogInfo("MpcSStep", " senderIndex", senderIndex, "selfIndex", selfIndex)

		rpkShare, err := msStep.getRPkShare(senderIndex)
		if err != nil {
			log.SyslogErr("msStep.getRPkShare", " error", err.Error())
		}

		gpkShare, err := msStep.getGPKShare(senderIndex)
		if err != nil {
			log.SyslogErr("msStep.getGPKShare", " error", err.Error())
		}

		m, err := msStep.getm()
		if err != nil {
			log.SyslogErr("msStep.getm", " error", err.Error())
		}

		bContentCheck, err := msStep.checkContent(&sshare, m, rpkShare, gpkShare)
		if err != nil {
			log.SyslogErr("msStep.checkContent", " error", err.Error())
		}

		if bContentCheck {
			log.SyslogInfo("check content of sshare successfully", " senderIndex", senderIndex)
		} else {
			log.SyslogErr("check content of sshare fail", " senderIndex", senderIndex)
		}

		if schcomm.MaliceSSigRcv && bVerifySig {
			bVerifySig = false
		}

		if schcomm.MaliceSContentRcv && bContentCheck {
			bContentCheck = false
		}
		// 3. write error sshare
		// 3.1 write error count
		// 3.2 write error info
		if !bContentCheck || !bVerifySig {
			msStep.SShareErrNum += 1

			msStep.sshareKOIndex = append(msStep.sshareKOIndex, senderIndex)

			sshareErrInfo := make([]big.Int, 5)
			// sendIndex, rvcIndex, sshare, r, s
			sshareErrInfo[0] = *big.NewInt(0).SetInt64(int64(senderIndex))
			sshareErrInfo[1] = *big.NewInt(0).SetInt64(int64(selfIndex))
			sshareErrInfo[2] = sshare
			sshareErrInfo[3] = r
			sshareErrInfo[4] = s

			// save error info
			keyErrInfo := mpcprotocol.SShareErrInfos + strconv.Itoa(int(msStep.SShareErrNum)-1)
			err := msStep.mpcResult.SetValue(keyErrInfo, sshareErrInfo)
			if err != nil {
				log.SyslogErr("@@@@@msStep.mpcResult.SetValue save fail", " err", err.Error(), "key", keyErrInfo)
			} else {
				if msStep.SShareErrNum > 0 {
					sshareErrInfoStr := fmt.Sprintf("%#v", sshareErrInfo)
					log.SyslogWarning("@@@@@msStep.mpcResult.SetValue save success", "key", keyErrInfo, "value", sshareErrInfoStr)
				}
			}

		} else {
			log.SyslogInfo("@@@@check sshare successfully", " senderIndex", senderIndex)
			msStep.sshareOKIndex = append(msStep.sshareOKIndex, senderIndex)

		}
		pointer.message[*msg.PeerID] = sshare

		// save error number errNum=0:no error.
		keyErrNum := mpcprotocol.SShareErrNum
		rskErrInfoNum := make([]big.Int, 1)
		rskErrInfoNum[0] = *big.NewInt(0).SetInt64(int64(msStep.SShareErrNum))
		err = msStep.mpcResult.SetValue(keyErrNum, rskErrInfoNum)
		if err != nil {
			log.SyslogErr("@@@@@msStep.mpcResult.SetValue save fail", " err", err.Error(), "key", keyErrNum, "value", rskErrInfoNum)
		} else {
			if msStep.SShareErrNum > 0 {
				log.SyslogWarning("@@@@@msStep.mpcResult.SetValue save success", "key", keyErrNum,
					"value", hexutil.Encode(rskErrInfoNum[0].Bytes()))
			}
		}
	}

	return true
}

func (msStep *MpcSStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	log.SyslogInfo("MpcSStep.FinishStep begin")
	err := msStep.BaseMpcStep.FinishStep()

	// save index for incentive and slash

	_, grpIdString, _ := osmconf.GetGrpId(msStep.mpcResult)

	allIndex, _ := osmconf.GetOsmConf().GetGrpElemsInxes(grpIdString)
	tempIndex := osmconf.Difference(*allIndex, msStep.sshareOKIndex)
	msStep.sshareNOIndex = osmconf.Difference(tempIndex, msStep.sshareKOIndex)

	okIndex := make([]big.Int, len(msStep.sshareOKIndex))
	koIndex := make([]big.Int, len(msStep.sshareKOIndex))
	noIndex := make([]big.Int, len(msStep.sshareNOIndex))

	for i, value := range msStep.sshareOKIndex {
		okIndex[i].SetInt64(int64(value))
	}

	for i, value := range msStep.sshareKOIndex {
		koIndex[i].SetInt64(int64(value))
	}

	for i, value := range msStep.sshareNOIndex {
		noIndex[i].SetInt64(int64(value))
	}

	msStep.mpcResult.SetValue(mpcprotocol.SOKIndex, okIndex)
	msStep.mpcResult.SetValue(mpcprotocol.SKOIndex, koIndex)
	msStep.mpcResult.SetValue(mpcprotocol.SNOIndex, noIndex)

	if err != nil {
		_, retHash := msStep.BaseMpcStep.GetSignedDataHash(result)
		msStep.BaseMpcStep.ShowNotArriveNodes(retHash, mpc.SelfNodeId())

		return err
	}

	for i := 0; i < msStep.signNum; i++ {
		pointer := msStep.messages[i].(*mpcSGenerator)
		// MpcS

		log.SyslogInfo("%%%%%%%%%%%%%%%%%%%%MPCSStep", "s", hexutil.Encode(pointer.result.Bytes()))

		err = result.SetValue(msStep.resultKeys[i], []big.Int{pointer.result})
		if err != nil {
			log.SyslogErr("MpcSStep::FinishStep", "MpcSStep.FinishStep, SetValue fail. err", err.Error())
			return err
		}
	}

	log.SyslogInfo("MpcSStep.FinishStep succeed")
	return nil
}

func (msStep *MpcSStep) checkContent(sshare, m *big.Int, rpkShare, gpkShare mpcprotocol.CurvePointer) (bool, error) {
	if sshare == nil || m == nil {
		return false, errors.New("sshare is nil or m is nil")
	}

	smpcer := msStep.schnorrMpcer

	if !smpcer.IsOnCurve(rpkShare) || !smpcer.IsOnCurve(gpkShare) {
		return false, errors.New("rpkShare or gpkShare is invalid pk or gpkShare is invalid pk")
	}

	sshareG, _ := smpcer.SkG(sshare)
	mPkShare, _ := smpcer.MulPK(m, gpkShare)

	if !smpcer.IsOnCurve(mPkShare) {
		return false, errors.New("mPkShare is invalid pk or gpkShare is invalid pk")
	}

	pkTemp, err := smpcer.Add(rpkShare, mPkShare)
	if err != nil {
		return false, errors.New("add rpkShare mPkShare error")
	}
	left := sshareG
	right := pkTemp

	return smpcer.Equal(left, right), nil
}

func (msStep *MpcSStep) getRPkShare(index uint16) (mpcprotocol.CurvePointer, error) {

	key := mpcprotocol.RPkShare + strconv.Itoa(int(index))

	log.SyslogInfo("getRPkShare", "index", index, "key", key)
	pkBytes, err := msStep.mpcResult.GetByteValue(key)
	if err != nil {
		log.SyslogErr("getRPkShare", "err", err.Error())
	}
	log.SyslogDebug("MpcSStep getRPkShare", "pkBytes", hexutil.Encode(pkBytes))
	return msStep.schnorrMpcer.UnMarshPt(pkBytes)
}

func (msStep *MpcSStep) getm() (*big.Int, error) {
	// check signVerify
	result := msStep.mpcResult
	M, err := result.GetByteValue(mpcprotocol.MpcM)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "ack MpcAckRSStep get MpcM . err", err.Error())
		return &big.Int{}, err
	}

	hashMBytes := sha256.Sum256(M)

	// rpk : R
	rpkBytes, _ := result.GetByteValue(mpcprotocol.RPk)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	//buffer.Write(M[:])
	buffer.Write(hashMBytes[:])
	buffer.Write(rpkBytes)
	mTemp := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mTemp[:])
	m = m.Mod(m, msStep.schnorrMpcer.GetMod())
	return m, nil
}

func (msStep *MpcSStep) getGPKShare(index uint16) (mpcprotocol.CurvePointer, error) {

	_, grpIdString, err := osmconf.GetGrpId(msStep.mpcResult)
	if err != nil {
		return nil, err
	}

	gpkShareBytes, err := osmconf.GetOsmConf().GetPKShareBytes(grpIdString, index, msStep.CurveType())
	if err != nil {
		return nil, err
	}
	return msStep.schnorrMpcer.UnMarshPt(gpkShareBytes)
}
