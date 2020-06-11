package storemanmpc

import (
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/rlp"
	"github.com/wanchain/schnorr-mpc/storeman/btc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"github.com/wanchain/schnorr-mpc/storeman/storemanmpc/step"
)

//send create LockAccount from leader
func requestTxSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, peerCount uint16, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)

	mpc := createMpcContext(mpcID, peers, result)

	requestMpc := step.CreateRequestMpcStep(&mpc.peers, peerCount, mpcprotocol.MpcTXSignLeader)
	// Not count receive message from self.
	requestMpc.SetWaiting(int(peerCount))

	mpcReady := step.CreateMpcReadyStep(&mpc.peers)
	return generateTxSignMpc(mpc, requestMpc, mpcReady, peerCount)
}

//get message from leader and create Context
func acknowledgeTxSignMpc(mpcID uint64, peers []mpcprotocol.PeerInfo, peerCount uint16, preSetValue ...MpcValue) (*MpcContext, error) {
	result := createMpcBaseMpcResult()
	result.InitializeValue(preSetValue...)
	mpc := createMpcContext(mpcID, peers, result)
	AcknowledgeMpc := step.CreateAcknowledgeMpcStep(&mpc.peers, mpcprotocol.MpcTXSignPeer)
	// wait 0
	mpcReady := step.CreateGetMpcReadyStep(&mpc.peers)
	// wait 1
	return generateTxSignMpc(mpc, AcknowledgeMpc, mpcReady, peerCount)
}

func generateTxSignMpc(mpc *MpcContext, firstStep MpcStepFunc, readyStep MpcStepFunc, peerCount uint16) (*MpcContext, error) {
	log.SyslogInfo("generateTxSignMpc begin")

	signNum, err := getSignNumFromTxInfo(mpc)
	if err != nil {
		return nil, err
	}

	JRJZ := step.CreateTXSignJR_JZ_Step(mpcprotocol.MPCDegree, &mpc.peers, signNum)
	JRJZ.SetWaiting(int(peerCount + 1))

	pointStepPreValueKeys := mpcprotocol.GetPreSetKeyArr(mpcprotocol.MpcSignA0, signNum)
	pointStepResultKeys := mpcprotocol.GetPreSetKeyArr(mpcprotocol.MpcSignAPoint, signNum)
	AGPoint := step.CreateMpcPoint_Step(&mpc.peers, pointStepPreValueKeys, pointStepResultKeys)
	AGPoint.SetWaiting(int(peerCount + 1))

	lagStepPreValueKeys := mpcprotocol.GetPreSetKeyArr(mpcprotocol.MpcSignARSeed, signNum)
	lagStepResultKeys := mpcprotocol.GetPreSetKeyArr(mpcprotocol.MpcSignARResult, signNum)
	ARLag := step.CreateTXSign_Lagrange_Step(&mpc.peers, lagStepPreValueKeys, lagStepResultKeys)
	ARLag.SetWaiting(int(peerCount + 1))

	TXSignLag := step.CreateTxSign_CalSignStep(&mpc.peers, mpcprotocol.MpcTxSignResult, signNum)
	TXSignLag.SetWaiting(int(peerCount + 1))

	mpc.setMpcStep(firstStep, readyStep, JRJZ, AGPoint, ARLag, TXSignLag)

	for index, step := range mpc.MpcSteps {
		step.SetStepId(index)
		step.SetWaitAll(false)
	}
	return mpc, nil
}

func getSignNumFromTxInfo(mpc *MpcContext) (int, error) {
	signNum := 1
	chainType, err := mpc.mpcResult.GetByteValue(mpcprotocol.MpcChainType)
	if err != nil {
		log.SyslogErr("getSignNumFromTxInfo, get chainType fail", "err", err.Error())
		return 0, err
	}

	if string(chainType) == "BTC" {
		btcTxData, err := mpc.mpcResult.GetByteValue(mpcprotocol.MpcTransaction)
		if err != nil {
			log.SyslogErr("getSignNumFromTxInfo, get tx rlp date fail", "err", err.Error())
			return 0, err
		}

		var args btc.MsgTxArgs
		err = rlp.DecodeBytes(btcTxData, &args)
		if err != nil {
			log.SyslogErr("getSignNumFromTxInfo, decode tx rlp data fail", "err", err.Error())
			return 0, err
		}

		signNum = len(args.TxIn)
	}

	log.SyslogInfo("getSignNumFromTxInfo, succeed", "signNum", signNum)
	return signNum, nil
}
