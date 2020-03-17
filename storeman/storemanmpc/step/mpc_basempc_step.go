package step

import (
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
)

type MpcMessageGenerator interface {
	initialize(*[]mpcprotocol.PeerInfo, mpcprotocol.MpcResultInterface) error
	calculateResult() error
}

type BaseMpcStep struct {
	BaseStep
	messages []MpcMessageGenerator
}

func CreateBaseMpcStep(peers *[]mpcprotocol.PeerInfo, messageNum int) *BaseMpcStep {
	return &BaseMpcStep{
		*CreateBaseStep(peers, -1),
		make([]MpcMessageGenerator, messageNum)}
}

func (mpcStep *BaseMpcStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	for _, message := range mpcStep.messages {
		err := message.initialize(mpcStep.peers, result)
		if err != nil {
			log.SyslogErr("BaseMpcStep, init msg fail. err:%s", err.Error())
			return err
		}
	}

	return nil
}

func (mpcStep *BaseMpcStep) FinishStep() error {
	err := mpcStep.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	for _, message := range mpcStep.messages {
		err := message.calculateResult()
		if err != nil {
			log.SyslogErr("BaseMpcStep, calculate msg result fail. err:%s", err.Error())
			return err
		}
	}

	return nil
}

func (mpcStep *BaseMpcStep) ShowNotArriveNodes(hash common.Hash, selfNodeId *discover.NodeID){
	if len(mpcStep.notRecvPeers) != 0 {
		for peerId,_ := range mpcStep.notRecvPeers {
			if peerId != *selfNodeId {
				//log.SyslogErr(fmt.Sprintf("Not received data from %v", peerId.String()))
				log.SyslogErr("ShowNotArriveNodes","hash(signedData)",hash.String(),"Not received data from ", peerId.String())
			}
		}
	}
}


func (mpcStep *BaseMpcStep) GetSignedDataHash(result mpcprotocol.MpcResultInterface)(error,common.Hash){
	var retHash = common.Hash{}
	// check signVerify
	M, err := result.GetByteValue(mpcprotocol.MpcM)
	if err != nil {
		log.SyslogErr("GetSignedDataHash . err", err.Error())
		return err,retHash
	}
	retHash = sha256.Sum256(M)
	return nil, retHash
}
