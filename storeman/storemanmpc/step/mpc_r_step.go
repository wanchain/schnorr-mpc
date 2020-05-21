package step

import (
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

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

	_,grpIdString,_ := osmconf.GetGrpId(addStep.mpcResult)

	allIndex,_ := osmconf.GetOsmConf().GetGrpElemsInxes(grpIdString)
	tempIndex := osmconf.Difference(*allIndex,addStep.rpkshareOKIndex)
	addStep.rpkshareNOIndex = osmconf.Difference(tempIndex,addStep.rpkshareKOIndex)
	
	log.Info(">>>>>>MpcPointStep", "allIndex", allIndex)
	log.Info(">>>>>>MpcPointStep", "rpkshareOKIndex", addStep.rpkshareOKIndex)
	log.Info(">>>>>>MpcPointStep", "rpkshareKOIndex", addStep.rpkshareKOIndex)
	log.Info(">>>>>>MpcPointStep", "rpkshareNOIndex", addStep.rpkshareNOIndex)
	
	okIndex := make([]big.Int,len(addStep.rpkshareOKIndex))
	koIndex := make([]big.Int,len(addStep.rpkshareKOIndex))
	noIndex := make([]big.Int,len(addStep.rpkshareNOIndex))
	
	for i,value := range addStep.rpkshareOKIndex{
		okIndex[i].SetInt64(int64(value))
	}
	
	for i,value := range addStep.rpkshareKOIndex{
		koIndex[i].SetInt64(int64(value))
	}
	
	for i,value := range addStep.rpkshareNOIndex{
		noIndex[i].SetInt64(int64(value))
	}
	
	addStep.mpcResult.SetValue(mpcprotocol.ROKIndex,okIndex)
	addStep.mpcResult.SetValue(mpcprotocol.RKOIndex,koIndex)
	addStep.mpcResult.SetValue(mpcprotocol.RNOIndex,noIndex)
	
	if err != nil {
		_,retHash := addStep.BaseMpcStep.GetSignedDataHash(result)
		addStep.BaseMpcStep.ShowNotArriveNodes(retHash,mpc.SelfNodeId())
		return err
	}

	return nil
}
