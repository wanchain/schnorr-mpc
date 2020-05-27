package step

import (
	"bytes"
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type MpcRRcvInterStep struct {
	BaseStep
	rcvColMap map[*discover.NodeID]*big.Int
	rcvCol    *big.Int
}

func CreateMpcRRcvInterStep(peers *[]mpcprotocol.PeerInfo) *MpcRRcvInterStep {
	log.SyslogInfo("CreateMpcRRcvInterStep begin")

	mpc := &MpcRRcvInterStep{
		*CreateBaseStep(peers, -1),
		make(map[*discover.NodeID]*big.Int, 0),
		nil}
	return mpc
}

func (ptStep *MpcRRcvInterStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("MpcRRcvInterStep.InitStep begin")
	ptStep.BaseStep.InitStep(result)

	ret, err := result.GetValue(mpcprotocol.RRcvedColl)
	if err != nil {
		log.SyslogErr("MpcRRcvInterStep", "InitStep.getValue error", err.Error())
		return err
	}
	if len(ret) == 0 {
		log.SyslogErr("MpcRRcvInterStep", "GetValue len(ret)", len(ret))
		return err
	}
	ptStep.rcvCol = &ret[0]
	log.SyslogInfo("MpcRRcvInterStep.InitStep end")
	return nil
}

func (ptStep *MpcRRcvInterStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("CreateMpcRRcvInterStep.CreateMessage begin")
	message := make([]mpcprotocol.StepMessage, 1)
	message[0].MsgCode = mpcprotocol.MPCMessage
	message[0].PeerID = nil

	var buf bytes.Buffer
	buf.Write(ptStep.rcvCol.Bytes())
	h := sha256.Sum256(buf.Bytes())

	prv, _ := osmconf.GetOsmConf().GetSelfPrvKey()
	r, s, _ := schnorrmpc.SignInternalData(prv, h[:])

	message[0].Data = make([]big.Int, 3)
	message[0].Data[0] = *ptStep.rcvCol
	message[0].Data[1] = *r
	message[0].Data[2] = *s

	log.SyslogInfo("MpcRRcvInterStep.CreateMessage end")
	return message
}

func (ptStep *MpcRRcvInterStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("MpcRRcvInterStep.HandleMessage begin")
	r := msg.Data[1]
	s := msg.Data[2]

	var buf bytes.Buffer
	buf.Write(msg.Data[0].Bytes())
	h := sha256.Sum256(buf.Bytes())

	_, grpIdStr, err := osmconf.GetGrpId(ptStep.mpcResult)
	if err != nil {
		log.SyslogErr("MpcRRcvInterStep", "HandleMessage error", err.Error())
	}

	senderPk, err := osmconf.GetOsmConf().GetPKByNodeId(grpIdStr, msg.PeerID)
	if err != nil {
		log.SyslogErr("MpcRRcvInterStep", "GetPKByNodeId error", err.Error())
	}

	bVerifySig := schnorrmpc.VerifyInternalData(senderPk, h[:], &r, &s)

	if bVerifySig {
		log.SyslogInfo("MpcRRcvInterStep::HandleMessage check sig success")
		ptStep.rcvColMap[msg.PeerID] = &msg.Data[0]
	} else {
		log.SyslogErr("......MpcRRcvInterStep::HandleMessage check sig fail")
	}

	// update no work indexes.
	log.SyslogInfo("MpcRRcvInterStep.HandleMessage end")
	return true
}

func (ptStep *MpcRRcvInterStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	log.SyslogInfo("MpcRRcvInterStep.FinishStep begin")

	// compute the intersec and save
	err := ptStep.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	var bigs []big.Int
	for _, rcvCol := range ptStep.rcvColMap {
		bigs = append(bigs, *rcvCol)
	}

	bigInter, err := osmconf.InterSecByIndexes(&bigs)
	if err != nil {
		log.SyslogErr("FinishStep", "error", err.Error())
		return err
	}

	err = result.SetValue(mpcprotocol.RRcvedCollInter, []big.Int{*bigInter})
	if err != nil {
		log.SyslogErr("FinishStep", "SetValue error", err.Error())
		return err
	}
	log.SyslogInfo("MpcRRcvInterStep.FinishStep succeed")

	return nil
}
