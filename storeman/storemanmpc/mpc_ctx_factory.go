package storemanmpc

import (
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
)

type MpcCtxFactory struct {
}

func (*MpcCtxFactory) CreateContext(ctxType int,
	mpcID uint64,
	peers []mpcprotocol.PeerInfo,
	peerCurCount uint16,
	preSetValue ...MpcValue) (MpcInterface, error) {

	log.Info("\n\n\n")
	log.SyslogInfo("===================================== CreateContext=====================================")
	log.SyslogInfo("CreateContext", "ctxType", ctxType, "peerCurCount", peerCurCount)
	for i := 0; i < len(preSetValue); i++ {
		if preSetValue[i].Key != mpcprotocol.MpcPrivateShare {
			if preSetValue[i].Value != nil {
				//log.Info("preSetValue", "key", preSetValue[i].Key, "value", preSetValue[i].Value)
				log.SyslogInfo("preSetValue", "key", preSetValue[i].Key, "value", hexutil.Encode(preSetValue[i].Value[0].Bytes()))
			} else if preSetValue[i].ByteValue != nil {
				//log.Info("preSetValue", "key", preSetValue[i].Key, "bytevalue", preSetValue[i].ByteValue)
				log.SyslogInfo("preSetValue", "key", preSetValue[i].Key, "bytevalue", hexutil.Encode(preSetValue[i].ByteValue))
			}
		}

	}
	log.SyslogInfo("===================================== CreateContext=====================================")
	log.Info("\n\n\n")

	switch ctxType {
	//case mpcprotocol.MpcGPKLeader:
	//	return reqGPKMpc(mpcID, peers, preSetValue...)
	//case mpcprotocol.MpcGPKPeer:
	//	return ackGPKMpc(mpcID, peers, preSetValue...)

	case mpcprotocol.MpcSignLeader:
		return reqSignMpc(mpcID, peers, peerCurCount, preSetValue...)
	case mpcprotocol.MpcSignPeer:
		return ackSignMpc(mpcID, peers, peerCurCount, preSetValue...)
	}

	return nil, mpcprotocol.ErrContextType
}
