package storemanmpc

import (
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
)

type MpcTestCtxFactory struct {
}

func (*MpcTestCtxFactory) CreateContext(ctxType int, mpcID uint64, peers []mpcprotocol.PeerInfo, preSetValue ...MpcValue) (MpcInterface, error) {
	switch ctxType {
	case mpcprotocol.MpcCreateLockAccountLeader:
		return testCreatep2pMpc(mpcID, peers, preSetValue...)

	case mpcprotocol.MpcCreateLockAccountPeer:
		return acknowledgeCreatep2pMpc(mpcID, peers, preSetValue...)

	case mpcprotocol.MpcTXSignLeader:
		return requestTxSignMpc(mpcID, peers, uint16(0), preSetValue...)

	case mpcprotocol.MpcTXSignPeer:
		return acknowledgeTxSignMpc(mpcID, peers, uint16(0), preSetValue...)
	}

	return nil, mpcprotocol.ErrContextType
}
