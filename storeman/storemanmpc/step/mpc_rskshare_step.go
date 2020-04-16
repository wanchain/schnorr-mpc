package step

import (
	"crypto/ecdsa"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type MpcRSKShare_Step struct {
	BaseMpcStep
}

func CreateMpcRSKShareStep(degree int, peers *[]mpcprotocol.PeerInfo) *MpcRSKShare_Step {
	mpc := &MpcRSKShare_Step{*CreateBaseMpcStep(peers, 1)}
	mpc.messages[0] = createSkPolyValue(degree, len(*peers))
	return mpc
}

func (rss *MpcRSKShare_Step) CreateMessage() []mpcprotocol.StepMessage {
	message := make([]mpcprotocol.StepMessage, len(*rss.peers))
	skpv := rss.messages[0].(*RandomPolynomialValue)
	for i := 0; i < len(*rss.peers); i++ {
		message[i].MsgCode = mpcprotocol.MPCMessage
		message[i].PeerID = &(*rss.peers)[i].PeerID
		message[i].Data = make([]big.Int, 1)
		message[i].Data[0] = skpv.polyValue[i]
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
	seed := rss.getPeerSeed(msg.PeerID)
	if seed == 0 {
		log.SyslogErr("MpcJRSS_Step::HandleMessage", " can't find peer seed. peerID", msg.PeerID.String())
	}

	skpv := rss.messages[0].(*RandomPolynomialValue)
	_, exist := skpv.message[seed]
	if exist {
		log.SyslogErr("MpcJRSS_Step::HandleMessage"," can't find msg . peerID",msg.PeerID.String()," seed",seed)
		return false
	}

	skpv.message[seed] = msg.Data[0] //message.Value
	return true
}
