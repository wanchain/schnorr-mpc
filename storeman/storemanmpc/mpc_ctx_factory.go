package storemanmpc

import (
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
)

type MpcCtxFactory struct {
}

func (*MpcCtxFactory) CreateContext(ctxType int, mpcID uint64, peers []mpcprotocol.PeerInfo, curPeerCount uint16, preSetValue ...MpcValue) (MpcInterface, error) {
	switch ctxType {
	case mpcprotocol.MpcCreateLockAccountLeader:
		return requestCreateLockAccountMpc(mpcID, peers, preSetValue...)
	case mpcprotocol.MpcCreateLockAccountPeer:
		return acknowledgeCreateLockAccountMpc(mpcID, peers, preSetValue...)

	case mpcprotocol.MpcTXSignLeader:
		return requestTxSignMpc(mpcID, peers, curPeerCount, preSetValue...)
	case mpcprotocol.MpcTXSignPeer:
		return acknowledgeTxSignMpc(mpcID, peers, curPeerCount, preSetValue...)
	}

	return nil, mpcprotocol.ErrContextType
}
