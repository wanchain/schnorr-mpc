package step


import (
	"crypto/ecdsa"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/shcnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRSKShare_Step struct {
	BaseMpcStep
}

func CreateMpcRSKShareStep(degree int, peers *[]mpcprotocol.PeerInfo) *MpcRSKShare_Step {
	mpc := &MpcRSKShare_Step{*CreateBaseMpcStep(peers, 1)}
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
	err = result.SetValue(mpcprotocol.RMpcPublicShare, []big.Int{*gpkShare.X, *gpkShare.Y})
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
	bVerifySig := crypto.VerifyInternalData(senderPk,sij.Bytes(),&r,&s)
	if !bVerifySig{
		log.SyslogErr("MpcRSKShare_Step::HandleMessage",
			" verify sk sig fail", msg.PeerID.String(),
			"groupId",grpIdString)
	}

	selfNodeId , _ := osmconf.GetOsmConf().GetSelfNodeId()
	xValue, _ := osmconf.GetOsmConf().GetXValueByNodeId(grpIdString,selfNodeId)

	// 2. check sij*G=si+a[i][0]*X+a[i][1]*X^2+...+a[i][n]*x^(n-1)

	// get send poly commit
	keyPolyCMG := mpcprotocol.MPCRPolyCMG + strconv.Itoa(int(senderIndex))
	pgBytes,_:= rss.mpcResult.GetByteValue(keyPolyCMG)

	//split the pk list
	pks, _ := shcnorrmpc.SplitPksFromBytes(pgBytes[:])
	sijgEval, _ := shcnorrmpc.EvalByPolyG(pks,uint16(len(pks)-1),xValue)
	sijg,_ := shcnorrmpc.SkG(&sij)

	if ok,_ := shcnorrmpc.PkEqual(sijg, sijgEval); !ok{
		// check Not success
		log.SyslogErr("MpcRSKShare_Step::HandleMessage",
			" verify sk data fail", msg.PeerID.String(),
			"groupId",grpIdString)
	}

	skpv := rss.messages[0].(*RandomPolynomialValue)
	_, exist := skpv.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcRSKShare_Step::HandleMessage"," can't find msg . peerID",
			msg.PeerID.String()," PeerID",*msg.PeerID)
		return false
	}

	// 3. write error s[i][j]

	skpv.message[*msg.PeerID] = msg.Data[0] //message.Value
	return true
}
