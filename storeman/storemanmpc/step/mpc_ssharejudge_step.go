package step

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcSSahreJudgeStep struct {
	BaseStep
	SSlshCount uint16
}

func CreateMpcSSahreJudgeStep(peers *[]mpcprotocol.PeerInfo) *MpcSSahreJudgeStep {
	return &MpcSSahreJudgeStep{
		*CreateBaseStep(peers, 0), 0}
}

func (ssj *MpcSSahreJudgeStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	ssj.BaseStep.InitStep(result)
	return nil
}

func (ssj *MpcSSahreJudgeStep) CreateMessage() []mpcprotocol.StepMessage {
	keyErrNum := mpcprotocol.SShareErrNum
	errNum, err := ssj.mpcResult.GetValue(keyErrNum)
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep CreateMessage get SShareErrNum fail", "key", keyErrNum)
	} else {
		log.SyslogInfo("MpcSSahreJudgeStep CreateMessage get SShareErrNum success", "key", keyErrNum, "value", errNum[0].Int64())
	}
	errNumInt64 := errNum[0].Int64()

	_, grpIdString, _ := osmconf.GetGrpId(ssj.mpcResult)

	var ret []mpcprotocol.StepMessage

	if errNumInt64 > 0 {

		leaderIndex, _ := osmconf.GetOsmConf().GetLeaderIndex(grpIdString)
		leaderPeerId, _ := osmconf.GetOsmConf().GetNodeIdByIndex(grpIdString, leaderIndex)

		for i := 0; i < int(errNumInt64); i++ {
			ret = make([]mpcprotocol.StepMessage, int(errNumInt64))
			keyErrInfo := mpcprotocol.SShareErrInfos + strconv.Itoa(int(i))
			errInfo, err := ssj.mpcResult.GetValue(keyErrInfo)
			if err != nil {
				log.SyslogErr("MpcSSahreJudgeStep CreateMessage get SShareErrInfos fail", "key", keyErrInfo)
			} else {
				log.SyslogInfo("MpcSSahreJudgeStep CreateMessage get SShareErrInfos success", "key", keyErrInfo, "value", errInfo)
			}

			data := make([]big.Int, 5)
			for j := 0; j < 5; j++ {
				data[j] = errInfo[j]
			}

			// send multi judge message to leader,since there are more than one error.
			ret[i] = mpcprotocol.StepMessage{MsgCode: mpcprotocol.MPCMessage,
				PeerID:    leaderPeerId,
				Peers:     nil,
				Data:      data,
				BytesData: nil}
		}
	} else {
		log.SyslogInfo("sshare judge there is NO error record to be judged.")
	}

	return ret
}

func (ssj *MpcSSahreJudgeStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {

	err := ssj.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	err = ssj.saveSlshCount(int(ssj.SSlshCount))
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "FinishStep err", err.Error())
		return err
	}

	if ssj.SSlshCount > 0 {
		return mpcprotocol.ErrSSlsh
	}
	return nil
}

func (ssj *MpcSSahreJudgeStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	senderIndex := int(msg.Data[0].Int64())
	rcvIndex := int(msg.Data[1].Int64())
	sshare := msg.Data[2]
	r := msg.Data[3]
	s := msg.Data[4]

	grpId, grpIdString, _ := osmconf.GetGrpId(ssj.mpcResult)

	senderPk, _ := osmconf.GetOsmConf().GetPK(grpIdString, uint16(senderIndex))
	err := schcomm.CheckPK(senderPk)
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "HandleMessage", err.Error())
	}
	// 1. check sig
	h := sha256.Sum256(sshare.Bytes())
	bVerifySig := schcomm.VerifyInternalData(senderPk, h[:], &r, &s)

	bSnderWrong := true
	if !bVerifySig {
		log.SyslogErr("MpcSSahreJudgeStep", "senderIndex", senderIndex,
			"rcvIndex", rcvIndex,
			"sshare", hex.EncodeToString(sshare.Bytes()),
			"r", hex.EncodeToString(r.Bytes()),
			"s", hex.EncodeToString(s.Bytes()))

		bSnderWrong = true
	}

	// 2. check s content
	rpkShare, _ := ssj.getRPkShare(uint16(senderIndex))
	gpkShare, _ := ssj.getGPKShare(uint16(senderIndex))
	m, _ := ssj.getm()
	bContentCheck, _ := ssj.checkContent(&sshare, m, rpkShare, gpkShare)

	if !bContentCheck {
		log.SyslogErr("MpcSSahreJudgeStep", "senderIndex", senderIndex,
			"rcvIndex", rcvIndex,
			"content error. bSnderWrong:", bSnderWrong)
		bSnderWrong = true
	} else {
		log.SyslogErr("MpcSSahreJudgeStep", "senderIndex", senderIndex,
			"rcvIndex", rcvIndex,
			"content error. bSnderWrong:", bSnderWrong)
		bSnderWrong = false
	}

	if !bContentCheck || !bVerifySig {
		ssj.SSlshCount += 1

		ssj.saveSlshProof(bSnderWrong, m, &sshare, &r, &s, senderIndex, rcvIndex, int(ssj.SSlshCount), rpkShare, gpkShare, grpId)
	}

	return true
}

func (ssj *MpcSSahreJudgeStep) checkContent(sshare, m *big.Int, rpkShare, gpkShare mpcprotocol.CurvePointer) (bool, error) {

	smpcer := ssj.schnorrMpcer
	sshareG, _ := smpcer.SkG(sshare)
	mPkShare, _ := smpcer.MulPK(m, gpkShare)

	pkTemp, _ := smpcer.Add(rpkShare, mPkShare)

	left := sshareG
	right := pkTemp
	return smpcer.Equal(left, right), nil
}

func (ssj *MpcSSahreJudgeStep) getRPkShare(index uint16) (mpcprotocol.CurvePointer, error) {

	key := mpcprotocol.RPkShare + strconv.Itoa(int(index))
	pkBytes, _ := ssj.mpcResult.GetByteValue(key)

	//return crypto.ToECDSAPub(pkBytes), nil
	return ssj.schnorrMpcer.UnMarshPt(pkBytes)
}

func (ssj *MpcSSahreJudgeStep) getm() (*big.Int, error) {
	// check signVerify
	result := ssj.mpcResult
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

	return m, nil
}

func (ssj *MpcSSahreJudgeStep) getGPKShare(index uint16) (mpcprotocol.CurvePointer, error) {
	//

	_, grpIdString, err := osmconf.GetGrpId(ssj.mpcResult)
	if err != nil {
		return nil, err
	}

	gpkShareBytes, err := osmconf.GetOsmConf().GetPKShareBytes(grpIdString, index)
	if err != nil {
		return nil, err
	}
	return ssj.schnorrMpcer.UnMarshPt(gpkShareBytes)
}

func (ssj *MpcSSahreJudgeStep) saveSlshCount(slshCount int) error {

	sslshValue := make([]big.Int, 1)
	sslshValue[0] = *big.NewInt(0).SetInt64(int64(ssj.SSlshCount))

	key := mpcprotocol.MPCSSlshProofNum
	err := ssj.mpcResult.SetValue(key, sslshValue)
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "save MPCSSlshProofNum", err.Error(), "key", key)
		return err
	} else {
		log.SyslogErr("MpcSSahreJudgeStep", "save MPCSSlshProofNum success key", key)
	}

	return nil
}

func (ssj *MpcSSahreJudgeStep) saveSlshProof(isSnder bool,
	m, sshare, r, s *big.Int,
	sndrIndex, rcvrIndex, slshCount int,
	rpkShare, gpkShare mpcprotocol.CurvePointer, grp []byte) error {

	sslshValue := make([]big.Int, 7)
	if isSnder {
		sslshValue[0] = *schcomm.BigOne
	} else {
		sslshValue[0] = *schcomm.BigZero
	}

	sslshValue[1] = *m
	sslshValue[2] = *sshare
	sslshValue[3] = *r
	sslshValue[4] = *s
	sslshValue[5] = *big.NewInt(0).SetInt64(int64(sndrIndex))
	sslshValue[6] = *big.NewInt(0).SetInt64(int64(rcvrIndex))

	smpcer := ssj.schnorrMpcer
	// rpkShare, gpkShare, grpId
	var sslshByte bytes.Buffer
	//sslshByte.Write(crypto.FromECDSAPub(rpkShare))
	//sslshByte.Write(crypto.FromECDSAPub(gpkShare))
	rpkShareBytes, err := smpcer.MarshPt(rpkShare)
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "MarshPt(rpkShare) err ", err.Error())
		return err
	}
	gpkShareBytes, err := smpcer.MarshPt(gpkShare)
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "MarshPt(gpkShare) err ", err.Error())
		return err
	}
	sslshByte.Write(rpkShareBytes)
	sslshByte.Write(gpkShareBytes)
	sslshByte.Write(grp[:])

	key1 := mpcprotocol.SSlshProof + strconv.Itoa(int(slshCount-1))
	err = ssj.mpcResult.SetValue(key1, sslshValue)
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "save SlshProof.SetValue err ", err.Error(), "key", key1)
		return err
	} else {
		log.SyslogErr("MpcSSahreJudgeStep", "save SlshProof.SetValue success ", "key", key1)
	}
	err = ssj.mpcResult.SetByteValue(key1, sslshByte.Bytes())
	if err != nil {
		log.SyslogErr("MpcSSahreJudgeStep", "saveSlshProof.SetByteValue err ", err.Error(), "key", key1)
		return err
	} else {
		log.SyslogErr("MpcSSahreJudgeStep", "save SlshProof.SetByteValue success ", "key", key1)
	}

	return nil
}
