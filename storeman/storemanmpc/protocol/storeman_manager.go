package protocol

import (
	"github.com/wanchain/schnorr-mpc/p2p/discover"
)

type StoremanManager interface {
	P2pMessage(*discover.NodeID, uint64, interface{}) error

	BroadcastMessage([]discover.NodeID, uint64, interface{}) error

	SelfNodeId() *discover.NodeID

	CreateKeystore(MpcResultInterface, *[]PeerInfo, string) error
}
