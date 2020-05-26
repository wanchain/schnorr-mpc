package storemanmpc

import (
	"github.com/wanchain/schnorr-mpc/log"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"github.com/wanchain/schnorr-mpc/storeman/storemanmpc/step"
)

//send create LockAccount from leader
func reqSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)
	mpc := createMpcContext(mpcID, peers, result)

	reqMpc := step.CreateRequestMpcStep(&mpc.peers, mpcprotocol.MpcSignLeader)
	reqMpc.SetWaiting(mpcprotocol.MpcSchnrThr)

	mpcReady := step.CreateMpcReadyStep(&mpc.peers)

	return generateTxSignMpc(mpc, reqMpc, mpcReady)
}

//get message from leader and create Context
func ackSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)
	mpc := createMpcContext(mpcID, peers, result)

	ackMpc := step.CreateAckMpcStep(&mpc.peers, mpcprotocol.MpcSignPeer)

	mpcReady := step.CreateGetMpcReadyStep(&mpc.peers)
	mpcReady.SetWaiting(0)

	return generateTxSignMpc(mpc, ackMpc, mpcReady)
}

func generateTxSignMpc(mpc *MpcContext, firstStep MpcStepFunc, readyStep MpcStepFunc) (*MpcContext, error) {
	log.SyslogInfo("generateTxSignMpc begin")

	accTypeStr := ""

	cmStep := step.CreateMpcPolycmStep(&mpc.peers)
	//cmStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	skShare := step.CreateMpcRSKShareStep(mpcprotocol.MPCDegree, &mpc.peers)
	// wait time out, in order for all node try best get most response, so each node can get the same poly value.
	// It is not enough for node to wait only MPCDegree response, the reason is above.

	skJudgeStep := step.CreateMpcRSkJudgeStep(&mpc.peers)
	skJudgeStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	RStep := step.CreateMpcRStep(&mpc.peers, accTypeStr)
	RStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	SStep := step.CreateMpcSStep(&mpc.peers, []string{mpcprotocol.MpcPrivateShare}, []string{mpcprotocol.MpcS})
	SStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	sshareJudgeStep := step.CreateMpcSSahreJudgeStep(&mpc.peers)
	sshareJudgeStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	ackRSStep := step.CreateAckMpcRSStep(&mpc.peers, accTypeStr)
	ackRSStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	mpc.setMpcStep(firstStep,
		readyStep,
		cmStep,
		skShare,
		skJudgeStep,
		RStep,
		SStep,
		sshareJudgeStep,
		ackRSStep)

	for stepId, stepItem := range mpc.MpcSteps {
		stepItem.SetWaiting(len(mpc.peers) + 1)
		stepItem.SetWaitAll(false)
		stepItem.SetStepId(stepId)
	}

	return mpc, nil
}
