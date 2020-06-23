package storemanmpc

import (
	"errors"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"github.com/wanchain/schnorr-mpc/storeman/storemanmpc/step"
)

//send create LockAccount from leader
func reqSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, peerCurCount uint16, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)
	mpc := createMpcContext(mpcID, peers, result)

	reqMpc := step.CreateRequestMpcStep(&mpc.peers, peerCurCount, mpcprotocol.MpcSignLeader)
	reqMpc.SetWaiting(int(peerCurCount))

	mpcReady := step.CreateMpcReadyStep(&mpc.peers)
	mpcReady.SetWaiting(0)

	return generateTxSignMpc(mpc, reqMpc, mpcReady, peerCurCount)
}

//get message from leader and create Context
func ackSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, peerCurCount uint16, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)
	mpc := createMpcContext(mpcID, peers, result)

	ackMpc := step.CreateAckMpcStep(&mpc.peers, mpcprotocol.MpcSignPeer)
	ackMpc.SetWaiting(0)

	mpcReady := step.CreateGetMpcReadyStep(&mpc.peers)
	mpcReady.SetWaiting(1)

	return generateTxSignMpc(mpc, ackMpc, mpcReady, peerCurCount)
}

func generateTxSignMpc(mpc *MpcContext, firstStep MpcStepFunc, readyStep MpcStepFunc, peerCurCount uint16) (*MpcContext, error) {
	log.SyslogInfo("generateTxSignMpc begin")

	result := mpc.mpcResult
	_, grpIdString, err := osmconf.GetGrpId(result)
	if err != nil {
		log.SyslogErr("generateTxSignMpc", "GetGrpId error", err.Error())
		return nil, err
	}

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	if threshold < uint16(1) {
		log.SyslogErr("generateTxSignMpc", "threshold error", threshold)
		return nil, errors.New("invalid threshold")
	}
	degree := threshold - 1

	accTypeStr := ""

	cmStep := step.CreateMpcPolycmStep(&mpc.peers)
	cmStep.SetWaiting(int(peerCurCount + 1))

	skShare := step.CreateMpcRSKShareStep(int(degree), &mpc.peers)
	skShare.SetWaiting(int(peerCurCount + 1)) // not broadcast, only need receive peerCurCount data.

	skJudgeStep := step.CreateMpcRSkJudgeStep(&mpc.peers)
	// only handle the first Rsk challenge or (timeout no challenge)
	skJudgeStep.SetWaiting(1)

	// add rrcvInter step
	rrcvInterStep := step.CreateMpcRRcvInterStep(&mpc.peers)
	rrcvInterStep.SetWaiting(int(peerCurCount + 1))

	// add rrcvInter judge step
	rrcvJudgeStep := step.CreateMpcRRcvJudgeStep(&mpc.peers)
	rrcvJudgeStep.SetWaiting(int(peerCurCount + 1))

	RStep := step.CreateMpcRStep(&mpc.peers, accTypeStr)
	RStep.SetWaiting(int(threshold))

	SStep := step.CreateMpcSStep(&mpc.peers, []string{mpcprotocol.MpcPrivateShare}, []string{mpcprotocol.MpcS})
	SStep.SetWaiting(int(threshold))

	sshareJudgeStep := step.CreateMpcSSahreJudgeStep(&mpc.peers)
	// only handle the first sshare challenge or (timeout no challenge)
	sshareJudgeStep.SetWaiting(1)

	ackRSStep := step.CreateAckMpcRSStep(&mpc.peers, accTypeStr)
	ackRSStep.SetWaiting(int(peerCurCount + 1))

	mpc.setMpcStep(firstStep,
		readyStep,
		cmStep,
		skShare,
		skJudgeStep,
		rrcvInterStep,
		rrcvJudgeStep,
		RStep,
		SStep,
		sshareJudgeStep,
		ackRSStep)

	for stepId, stepItem := range mpc.MpcSteps {
		//stepItem.SetWaiting(len(mpc.peers) + 1)
		stepItem.SetWaitAll(false)
		stepItem.SetStepId(stepId)
	}

	return mpc, nil
}
