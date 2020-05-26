package step

import (
	"bytes"
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRSkJudgeStep struct {
	BaseStep
	RSlshCount uint16
}

func CreateMpcRSkJudgeStep(peers *[]mpcprotocol.PeerInfo) *MpcRSkJudgeStep {
	return &MpcRSkJudgeStep{
		*CreateBaseStep(peers, 0), 0}
}

func (rsj *MpcRSkJudgeStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("Entering MpcRSkJudgeStep InitStep")
	rsj.BaseStep.InitStep(result)
	return nil
}

func (rsj *MpcRSkJudgeStep) CreateMessage() []mpcprotocol.StepMessage {
	keyErrNum := mpcprotocol.RSkErrNum
	errNum, _ := rsj.mpcResult.GetValue(keyErrNum)
	errNumInt64 := errNum[0].Int64()

	_, grpIdString, _ := osmconf.GetGrpId(rsj.mpcResult)

	var ret []mpcprotocol.StepMessage

	if errNumInt64 > 0 {

		leaderIndex, _ := osmconf.GetOsmConf().GetLeaderIndex(grpIdString)
		leaderPeerId, _ := osmconf.GetOsmConf().GetNodeIdByIndex(grpIdString, leaderIndex)

		for i := 0; i < int(errNumInt64); i++ {
			ret = make([]mpcprotocol.StepMessage, int(errNumInt64))
			keyErrInfo := mpcprotocol.RSkErrInfos + strconv.Itoa(int(i))
			errInfo, _ := rsj.mpcResult.GetValue(keyErrInfo)

			data := make([]big.Int, 5)
			for j := 0; j < 5; j++ {
				data[i] = errInfo[i]
			}

			// send multi judge message to leader,since there are more than one error.
			ret[i] = mpcprotocol.StepMessage{MsgCode: mpcprotocol.MPCMessage,
				PeerID:    leaderPeerId,
				Peers:     nil,
				Data:      data,
				BytesData: nil}
		}
	} else {
		log.SyslogInfo("MpcRSkJudgeStep there is on record need to be judged.")
	}

	return ret
}

func (rsj *MpcRSkJudgeStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {

	err := rsj.saveSlshCount(int(rsj.RSlshCount))
	if err != nil {
		log.SyslogErr("MpcRSkJudgeStep", "FinishStep err ", err.Error())
		return err
	}

	err = rsj.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	if rsj.RSlshCount > 0 {
		return mpcprotocol.ErrRSlsh
	}
	return nil
}

func (rsj *MpcRSkJudgeStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	senderIndex := int(msg.Data[0].Int64())
	rcvIndex := int(msg.Data[1].Int64())
	sij := msg.Data[2]
	r := msg.Data[3]
	s := msg.Data[4]

	grpId, grpIdString, _ := osmconf.GetGrpId(rsj.mpcResult)

	senderPk, _ := osmconf.GetOsmConf().GetPK(grpIdString, uint16(senderIndex))
	err := schnorrmpc.CheckPK(senderPk)
	if err != nil {
		log.SyslogErr("MpcRSkJudgeStep", "HandleMessage", err.Error())
	}
	// 1. check sig
	h := sha256.Sum256(sij.Bytes())
	bVerifySig := schnorrmpc.VerifyInternalData(senderPk, h[:], &r, &s)
	bSnderWrong := true

	if !bVerifySig {
		log.SyslogErr("MpcRSkJudgeStep", "HandleMessage.bVerifySig", bVerifySig, "bSnderWrong", true)
		bSnderWrong = true
	}

	// 2. check sij*G=si+a[i][0]*X+a[i][1]*X^2+...+a[i][n]*x^(n-1)

	// get send poly commit
	keyPolyCMG := mpcprotocol.RPolyCMG + strconv.Itoa(int(senderIndex))
	pgBytes, _ := rsj.mpcResult.GetByteValue(keyPolyCMG)
	sigs, _ := rsj.mpcResult.GetValue(keyPolyCMG)

	xValue, err := osmconf.GetOsmConf().GetXValueByIndex(grpIdString, uint16(rcvIndex))
	if err != nil {
		log.SyslogErr("MpcRSkJudgeStep", "HandleMessage.GetXValueByIndex", err.Error())
	}

	//split the pk list
	pks, _ := schnorrmpc.SplitPksFromBytes(pgBytes[:])
	sijgEval, _ := schnorrmpc.EvalByPolyG(pks, uint16(len(pks)-1), xValue)
	sijg, _ := schnorrmpc.SkG(&sij)

	bContentCheck := true
	if ok, _ := schnorrmpc.PkEqual(sijg, sijgEval); !ok {
		log.SyslogErr("MpcRSkJudgeStep", "bSnderWrong", bSnderWrong, "bContentCheck", bContentCheck)
		bSnderWrong = true
		bContentCheck = false
	} else {
		log.SyslogErr("MpcRSkJudgeStep", "bSnderWrong", bSnderWrong, "bContentCheck", bContentCheck)
		bSnderWrong = false
	}

	if !bContentCheck || !bVerifySig {
		rsj.RSlshCount += 1
		rsj.saveSlshProof(bSnderWrong, &sigs[0], &sigs[1], &sij, &r, &s, senderIndex, rcvIndex, int(rsj.RSlshCount), grpId, pgBytes, uint16(len(pks)))
	}

	return true
}

func (ssj *MpcRSkJudgeStep) saveSlshCount(slshCount int) error {

	sslshValue := make([]big.Int, 1)
	sslshValue[0] = *big.NewInt(0).SetInt64(int64(ssj.RSlshCount))

	key := mpcprotocol.RSlshProofNum + strconv.Itoa(int(ssj.RSlshCount))
	err := ssj.mpcResult.SetValue(key, sslshValue)
	if err != nil {
		log.SyslogErr("MpcRSkJudgeStep", "saveSlshCount err ", err.Error())
		return err
	}

	return nil
}

func (ssj *MpcRSkJudgeStep) saveSlshProof(isSnder bool,
	polyR, polyS, sij, r, s *big.Int,
	sndrIndex, rcvrIndex, slshCount int,
	grp []byte, polyCM []byte, polyCMLen uint16) error {

	sslshValue := make([]big.Int, 9)
	if isSnder {
		sslshValue[0] = *schnorrmpc.BigOne
	} else {
		sslshValue[0] = *schnorrmpc.BigZero
	}
	sslshValue[1] = *polyR
	sslshValue[2] = *polyS
	sslshValue[3] = *sij
	sslshValue[4] = *r
	sslshValue[5] = *s
	sslshValue[6] = *big.NewInt(0).SetInt64(int64(sndrIndex))
	sslshValue[7] = *big.NewInt(0).SetInt64(int64(rcvrIndex))
	sslshValue[8] = *big.NewInt(0).SetInt64(int64(polyCMLen))

	// polyG0, polyG1,polyG2,...polyGn + grpId
	var sslshByte bytes.Buffer
	sslshByte.Write(polyCM[:])
	sslshByte.Write(grp[:])

	key1 := mpcprotocol.RSlshProof + strconv.Itoa(int(slshCount))
	err := ssj.mpcResult.SetValue(key1, sslshValue)
	if err != nil {
		log.SyslogErr("MpcRSkJudgeStep", "saveSlshProof.SetValue", err.Error())
		return err
	}
	err = ssj.mpcResult.SetByteValue(key1, sslshByte.Bytes())
	if err != nil {
		log.SyslogErr("MpcRSkJudgeStep", "saveSlshProof.SetByteValue", err.Error())
		return err
	}
	return nil
}
