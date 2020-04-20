package step

import (
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRSkJudgeStep struct {
	BaseStep
}

func CreateMpcRSkJudgeStep(peers *[]mpcprotocol.PeerInfo) *MpcRSkJudgeStep {
	return &MpcRSkJudgeStep{
		*CreateBaseStep(peers, 0)}
}

func (rsj *MpcRSkJudgeStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	rsj.BaseStep.InitStep(result)
	return nil
}

func (rsj *MpcRSkJudgeStep) CreateMessage() []mpcprotocol.StepMessage {
	keyErrNum := mpcprotocol.MPCRSkErrNum
	errNum,_ := rsj.mpcResult.GetValue(keyErrNum)
	errNumInt64 := errNum[0].Int64()
	grpId,_ := rsj.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)

	var ret []mpcprotocol.StepMessage

	if errNumInt64 > 0 {

		leaderIndex,_ := osmconf.GetOsmConf().GetLeaderIndex(grpIdString)
		leaderPeerId,_:= osmconf.GetOsmConf().GetNodeIdByIndex(grpIdString,leaderIndex)

		for i:=0; i< int(errNumInt64); i++{
			ret = make([]mpcprotocol.StepMessage, int(errNumInt64))
			keyErrInfo := mpcprotocol.MPCRSkErrInfos + strconv.Itoa(int(i))
			errInfo,_:= rsj.mpcResult.GetValue(keyErrInfo)

			data := make([]big.Int, 5)
			for j:=0; j< 5; j++ {
				data[0] = errInfo[0]
			}

			// send multi judge message to leader,since there are more than one error.
			// todo only send to leader
			ret[i] = mpcprotocol.StepMessage{MsgCode: mpcprotocol.MPCMessage,
				PeerID:    leaderPeerId,
				Peers:     nil,
				Data:      data,
				BytesData: nil}
		}
	}

	return ret
}

func (rsj *MpcRSkJudgeStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := rsj.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	return nil
}

func (rsj *MpcRSkJudgeStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	senderIndex := int(msg.Data[0].Int64())
	rcvIndex := int(msg.Data[1].Int64())
	sij := msg.Data[2]
	r := msg.Data[3]
	s := msg.Data[4]

	grpId,_ := rsj.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)
	senderPk,_ := osmconf.GetOsmConf().GetPK(grpIdString,uint16(senderIndex))

	// 1. check sig
	bVerifySig := schnorrmpc.VerifyInternalData(senderPk,sij.Bytes(),&r,&s)
	if !bVerifySig{
		// sig error , todo sender error
		// 1. write slash poof
		// 2. save slash num
	}

	// 2. check sij*G=si+a[i][0]*X+a[i][1]*X^2+...+a[i][n]*x^(n-1)

	// get send poly commit
	keyPolyCMG := mpcprotocol.MPCRPolyCMG + strconv.Itoa(int(senderIndex))
	pgBytes,_:= rsj.mpcResult.GetByteValue(keyPolyCMG)

	xValue, _ := osmconf.GetOsmConf().GetXValueByIndex(grpIdString,uint16(rcvIndex))

	//split the pk list
	pks, _ := schnorrmpc.SplitPksFromBytes(pgBytes[:])
	sijgEval, _ := schnorrmpc.EvalByPolyG(pks,uint16(len(pks)-1),xValue)
	sijg,_ := schnorrmpc.SkG(&sij)

	if ok,_ := schnorrmpc.PkEqual(sijg, sijgEval); !ok{
		// todo sender error

	}else{
		// todo receiver error
	}

	return true
}
