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
	curveType uint8,
	preSetValue ...MpcValue) (MpcInterface, error) {

	log.Info("\n\n\n")
	log.SyslogInfo("===================================== CreateContext=====================================")
	log.SyslogInfo("CreateContext", "ctxType", ctxType, "peerCurCount", peerCurCount, "curveType", curveType)
	for i := 0; i < len(preSetValue); i++ {
		if preSetValue[i].Key != mpcprotocol.MpcPrivateShare {
			if preSetValue[i].Value != nil {
				log.SyslogInfo("preSetValue", "key", preSetValue[i].Key, "value", hexutil.Encode(preSetValue[i].Value[0].Bytes()))
			} else if preSetValue[i].ByteValue != nil {
				log.SyslogInfo("preSetValue", "key", preSetValue[i].Key, "bytevalue", hexutil.Encode(preSetValue[i].ByteValue))
			}
		}

	}
	log.SyslogInfo("===================================== CreateContext=====================================")
	log.Info("\n\n\n")

	switch ctxType {

	case mpcprotocol.MpcSignLeader:
		return reqSignMpc(mpcID, peers, peerCurCount, curveType, preSetValue...)
	case mpcprotocol.MpcSignPeer:
		return ackSignMpc(mpcID, peers, peerCurCount, curveType, preSetValue...)
	default:
		return nil, mpcprotocol.ErrContextType
	}
	return nil, mpcprotocol.ErrContextType
}
