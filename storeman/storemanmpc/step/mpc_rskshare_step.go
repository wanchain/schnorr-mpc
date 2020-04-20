package step


import (
	"crypto/ecdsa"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRSKShare_Step struct {
	BaseMpcStep
	RSkErrNum uint16
}

func CreateMpcRSKShareStep(degree int, peers *[]mpcprotocol.PeerInfo) *MpcRSKShare_Step {
	mpc := &MpcRSKShare_Step{*CreateBaseMpcStep(peers, 1),0}
	mpc.messages[0] = createSkPolyGen(degree, len(*peers))
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
		message[i].Data[0] = skpv.polyValue[i]

		// add sig for s[i][j]
		message[i].Data[1] = *skpv.polyValueSigR[i]
		message[i].Data[2] = *skpv.polyValueSigS[i]
	}

	return message
}

func (rss *MpcRSKShare_Step) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := rss.BaseMpcStep.FinishStep()
	if err != nil {
		return err
	}

	// gskshare
	skpv := rss.messages[0].(*RandomPolynomialValue)
	err = result.SetValue(mpcprotocol.RMpcPrivateShare, []big.Int{*skpv.result})
	if err != nil {
		return err
	}
	// gpkshare
	var gpkShare ecdsa.PublicKey
	gpkShare.X, gpkShare.Y = crypto.S256().ScalarBaseMult((*skpv.result).Bytes())
	err = result.SetByteValue(mpcprotocol.RMpcPublicShare, crypto.FromECDSAPub(&gpkShare))
	if err != nil {
		return err
	}

	return nil
}

func (rss *MpcRSKShare_Step) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	// todo
	// check s[i][j]
	// 1. check sig of s[i][j]
	// 2. check value of s[i]]j] with the poly commit
	// 3. if error , send to leader to judge
	grpId,_ := rss.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)
	senderPk, _ := osmconf.GetOsmConf().GetPKByNodeId(grpIdString,msg.PeerID)
	senderIndex,_ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString,msg.PeerID)

	// get data, r, s
	sij := msg.Data[0]
	r := msg.Data[1]
	s := msg.Data[2]

	// 1. check sig
	bVerifySig := schnorrmpc.VerifyInternalData(senderPk,sij.Bytes(),&r,&s)
	if !bVerifySig{
		log.SyslogErr("MpcRSKShare_Step::HandleMessage",
			" verify sk sig fail", msg.PeerID.String(),
			"groupId",grpIdString)
	}

	selfNodeId , _ := osmconf.GetOsmConf().GetSelfNodeId()
	selfIndex, _ := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	xValue, _ := osmconf.GetOsmConf().GetXValueByNodeId(grpIdString,selfNodeId)

	// 2. check sij*G=si+a[i][0]*X+a[i][1]*X^2+...+a[i][n]*x^(n-1)

	// get send poly commit
	keyPolyCMG := mpcprotocol.MPCRPolyCMG + strconv.Itoa(int(senderIndex))
	pgBytes,_:= rss.mpcResult.GetByteValue(keyPolyCMG)

	//split the pk list
	pks, _ := schnorrmpc.SplitPksFromBytes(pgBytes[:])
	sijgEval, _ := schnorrmpc.EvalByPolyG(pks,uint16(len(pks)-1),xValue)
	sijg,_ := schnorrmpc.SkG(&sij)

	if ok,_ := schnorrmpc.PkEqual(sijg, sijgEval); !ok{
		// check Not success
		log.SyslogErr("MpcRSKShare_Step::HandleMessage",
			" verify sk data fail", msg.PeerID.String(),
			"groupId",grpIdString)

		rss.RSkErrNum += 1

	}

	skpv := rss.messages[0].(*RandomPolynomialGen)
	_, exist := skpv.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcRSKShare_Step::HandleMessage"," can't find msg . peerID",
			msg.PeerID.String()," PeerID",*msg.PeerID)
		return false
	}

	// 3. write error s[i][j]
	// 3.1 write error count
	// 3.2 write error info
	if rss.RSkErrNum > 1 {
		rskErrInfo := make([]big.Int,5)
		// sendIndex, rvcIndex, s[i][j], r, s
		rskErrInfo[0] = *big.NewInt(0).SetInt64(int64(senderIndex))
		rskErrInfo[1] = *big.NewInt(0).SetInt64(int64(selfIndex))
		rskErrInfo[2] = sij
		rskErrInfo[3] =	r
		rskErrInfo[4] =	s

		keyErrInfo := mpcprotocol.MPCRSkErrInfos + strconv.Itoa(int(rss.RSkErrNum) -1)
		rss.mpcResult.SetValue(keyErrInfo,rskErrInfo)


		keyErrNum := mpcprotocol.MPCRSkErrNum
		rskErrInfoNum := make([]big.Int,1)
		rskErrInfoNum[0] = *big.NewInt(0).SetInt64(int64(rss.RSkErrNum))
		rss.mpcResult.SetValue(keyErrNum,rskErrInfoNum)
	}
	skpv.message[*msg.PeerID] = msg.Data[0] //message.Value
	return true
}
