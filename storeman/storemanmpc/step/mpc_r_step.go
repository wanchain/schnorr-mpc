package step

import mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"

type MpcRStep struct {
	MpcPointStep
	accType string
}

func CreateMpcRStep(peers *[]mpcprotocol.PeerInfo, accType string) *MpcRStep {
	mpc := &MpcRStep{MpcPointStep: *CreateMpcPointStep(peers,
		[]string{mpcprotocol.RPkShare},
		[]string{mpcprotocol.RPk}),
		accType: accType}
	return mpc
}

func (addStep *MpcRStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := addStep.MpcPointStep.FinishStep(result, mpc)

	if err != nil {
		_,retHash := addStep.BaseMpcStep.GetSignedDataHash(result)
		addStep.BaseMpcStep.ShowNotArriveNodes(retHash,mpc.SelfNodeId())
		return err
	}

	return nil
}
