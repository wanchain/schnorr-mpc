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

	_, grpIdString, err := osmconf.GetGrpId(result)
	if err != nil {
		log.SyslogErr("reqSignMpc", "GetGrpId error", err.Error())
		return nil, err
	}

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum(grpIdString)
	reqMpc.SetWaiting(int(threshold))

	mpcReady := step.CreateMpcReadyStep(&mpc.peers)

	return generateTxSignMpc(mpc, reqMpc, mpcReady, peerCurCount)
}

//get message from leader and create Context
func ackSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, peerCurCount uint16, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)
	mpc := createMpcContext(mpcID, peers, result)

	ackMpc := step.CreateAckMpcStep(&mpc.peers, mpcprotocol.MpcSignPeer)

	mpcReady := step.CreateGetMpcReadyStep(&mpc.peers)
	mpcReady.SetWaiting(0)

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
	//cmStep.SetWaiting(mpcprotocol.MpcSchnrThr)

	skShare := step.CreateMpcRSKShareStep(int(degree), &mpc.peers)
	// wait time out, in order for all node try best get most response, so each node can get the same poly value.
	// It is not enough for node to wait only MPCDegree response, the reason is above.

	skJudgeStep := step.CreateMpcRSkJudgeStep(&mpc.peers)
	skJudgeStep.SetWaiting(int(threshold))

	// add rrcvInter step
	rrcvInterStep := step.CreateMpcRRcvInterStep(&mpc.peers)

	// add rrcvInter judge step
	rrcvJudgeStep := step.CreateMpcRRcvJudgeStep(&mpc.peers)

	RStep := step.CreateMpcRStep(&mpc.peers, accTypeStr)
	RStep.SetWaiting(int(threshold))

	SStep := step.CreateMpcSStep(&mpc.peers, []string{mpcprotocol.MpcPrivateShare}, []string{mpcprotocol.MpcS})
	SStep.SetWaiting(int(threshold))

	sshareJudgeStep := step.CreateMpcSSahreJudgeStep(&mpc.peers)
	sshareJudgeStep.SetWaiting(int(threshold))

	ackRSStep := step.CreateAckMpcRSStep(&mpc.peers, accTypeStr)
	ackRSStep.SetWaiting(int(threshold))

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
		stepItem.SetWaiting(len(mpc.peers) + 1)
		stepItem.SetWaitAll(false)
		stepItem.SetStepId(stepId)
	}

	return mpc, nil
}
