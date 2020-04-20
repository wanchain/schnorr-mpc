package step

import (
	"encoding/hex"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
)

type MpcPointStep struct {
	BaseMpcStep
	resultKeys []string
	signNum    int
}

func CreateMpcPointStep(peers *[]mpcprotocol.PeerInfo, preValueKeys []string, resultKeys []string) *MpcPointStep {
	log.SyslogInfo("CreateMpcPointStep begin")

	signNum := len(preValueKeys)
	mpc := &MpcPointStep{*CreateBaseMpcStep(peers, signNum), resultKeys, signNum}

	for i := 0; i < signNum; i++ {
		mpc.messages[i] = createPointGenerator(preValueKeys[i])
	}

	return mpc
}

func (ptStep *MpcPointStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("MpcPointStep.CreateMessage begin")
	// add public key and r, s.
	message := make([]mpcprotocol.StepMessage, 1)
	message[0].MsgCode = mpcprotocol.MPCMessage
	message[0].PeerID = nil

	for i := 0; i < ptStep.signNum; i++ {
		pointer := ptStep.messages[i].(*mpcPointGenerator)
		message[0].BytesData = append(message[0].BytesData,crypto.FromECDSAPub(&pointer.seed))
	}

	return message
}

func (ptStep *MpcPointStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {

	log.SyslogInfo("MpcPointStep.HandleMessage begin ",
		"peerID", msg.PeerID.String(),
		"gpk x", hex.EncodeToString(msg.BytesData[0]))

	for i := 0; i < ptStep.signNum; i++ {
		pointer := ptStep.messages[i].(*mpcPointGenerator)
		_, exist := pointer.message[*msg.PeerID]
		if exist {
			log.SyslogErr("HandleMessage","MpcPointStep.HandleMessage, get msg from seed fail. peer", msg.PeerID.String())
			return false
		}

		pointer.message[*msg.PeerID] = *crypto.ToECDSAPub(msg.BytesData[i])
	}

	return true
}

func (ptStep *MpcPointStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	log.SyslogInfo("MpcPointStep.FinishStep begin")
	err := ptStep.BaseMpcStep.FinishStep()
	if err != nil {
		return err
	}

	for i := 0; i < ptStep.signNum; i++ {
		pointer := ptStep.messages[i].(*mpcPointGenerator)
		log.Info("generated gpk MpcPointStep::FinishStep",
			"result key", ptStep.resultKeys[i],
			"result value ", hexutil.Encode(crypto.FromECDSAPub(&pointer.result)))

		err = result.SetByteValue(ptStep.resultKeys[i], crypto.FromECDSAPub(&pointer.result))
		if err != nil {
			log.SyslogErr("HandleMessage","MpcPointStep.FinishStep, SetValue fail. err", err.Error())
			return err
		}
	}

	log.SyslogInfo("MpcPointStep.FinishStep succeed")
	return nil
}
