package step

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcSSahreJudgeStep struct {
	BaseStep
}

func CreateMpcSSahreJudgeStep(peers *[]mpcprotocol.PeerInfo) *MpcSSahreJudgeStep {
	return &MpcSSahreJudgeStep{
		*CreateBaseStep(peers, 0)}
}

func (ssj *MpcSSahreJudgeStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	ssj.BaseStep.InitStep(result)
	return nil
}

func (ssj *MpcSSahreJudgeStep) CreateMessage() []mpcprotocol.StepMessage {
	keyErrNum := mpcprotocol.MPCSShareErrNum
	errNum,_ := ssj.mpcResult.GetValue(keyErrNum)
	errNumInt64 := errNum[0].Int64()
	grpId,_ := ssj.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)

	var ret []mpcprotocol.StepMessage

	if errNumInt64 > 0 {

		leaderIndex,_ := osmconf.GetOsmConf().GetLeaderIndex(grpIdString)
		leaderPeerId,_:= osmconf.GetOsmConf().GetNodeIdByIndex(grpIdString,leaderIndex)

		for i:=0; i< int(errNumInt64); i++{
			ret = make([]mpcprotocol.StepMessage, int(errNumInt64))
			keyErrInfo := mpcprotocol.MPCSShareErrInfos + strconv.Itoa(int(i))
			errInfo,_:= ssj.mpcResult.GetValue(keyErrInfo)

			data := make([]big.Int, 5)
			for j:=0; j< 5; j++ {
				data[i] = errInfo[i]
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

func (ssj *MpcSSahreJudgeStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := ssj.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	return nil
}

func (ssj *MpcSSahreJudgeStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	senderIndex := int(msg.Data[0].Int64())
	rcvIndex := int(msg.Data[1].Int64())
	sshare := msg.Data[2]
	r := msg.Data[3]
	s := msg.Data[4]

	grpId,_ := ssj.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)
	senderPk,_ := osmconf.GetOsmConf().GetPK(grpIdString,uint16(senderIndex))

	// 1. check sig
	h := sha256.Sum256(sshare.Bytes())
	bVerifySig := schnorrmpc.VerifyInternalData(senderPk,h[:],&r,&s)
	if !bVerifySig{
		log.SyslogErr("MpcSSahreJudgeStep", "senderIndex",senderIndex,
			"rcvIndex",rcvIndex,
			"sshare",hex.EncodeToString(sshare.Bytes()),
			"r",hex.EncodeToString(r.Bytes()),
			"s",hex.EncodeToString(s.Bytes()))
		// sig error , todo sender error
		// 1. write slash poof
		// 2. save slash num
	}

	// 2. check s content
	rpkShare,_ := ssj.getRPkShare(uint16(senderIndex))
	gpkShare,_ := ssj.getGPKShare()
	m,_:= ssj.getm()
	bContentCheck,_ := ssj.checkContent(&sshare,m,rpkShare,gpkShare)

	if !bContentCheck{
		// content error, todo sender error
	}else{
		// todo receiver error
	}

	return true
}



func (ssj *MpcSSahreJudgeStep) checkContent(sshare, m *big.Int, rpkShare,gpkShare *ecdsa.PublicKey) (bool,error) {
	sshareG,_ := schnorrmpc.SkG(sshare)
	mPkShare, _ := schnorrmpc.SkMul(gpkShare,m)

	pkTemp := new(ecdsa.PublicKey)
	pkTemp.Curve = crypto.S256()
	pkTemp.X, pkTemp.Y = rpkShare.X, rpkShare.Y
	pkTemp.X, pkTemp.Y = crypto.S256().Add(pkTemp.X,pkTemp.Y,mPkShare.X,mPkShare.Y)

	left := sshareG
	right := pkTemp
	return schnorrmpc.PkEqual(left,right)
}

func (ssj *MpcSSahreJudgeStep) getRPkShare(index uint16) (*ecdsa.PublicKey,error) {

	key := mpcprotocol.RMpcPublicShare + strconv.Itoa(int(index))
	pkBytes,_ := ssj.mpcResult.GetByteValue(key)

	return crypto.ToECDSAPub(pkBytes),nil
}

func (ssj *MpcSSahreJudgeStep) getm() (*big.Int,error) {
	// check signVerify
	result := ssj.mpcResult
	M, err := result.GetByteValue(mpcprotocol.MpcM)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS","ack MpcAckRSStep get MpcM . err", err.Error())
		return &big.Int{}, err
	}

	hashMBytes := sha256.Sum256(M)

	// rpk : R
	rpkBytes,_ := result.GetByteValue(mpcprotocol.RPublicKeyResult)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	//buffer.Write(M[:])
	buffer.Write(hashMBytes[:])
	buffer.Write(rpkBytes)
	mTemp := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mTemp[:])

	return m,nil
}

func (ssj *MpcSSahreJudgeStep) getGPKShare() (*ecdsa.PublicKey,error) {
	//
	result := ssj.mpcResult
	gpkBytes, _ := result.GetByteValue(mpcprotocol.PublicKeyResult)

	return crypto.ToECDSAPub(gpkBytes[:]),nil
}