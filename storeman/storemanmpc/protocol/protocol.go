package protocol

import (
	"bytes"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"math/big"
	"time"
)

const (
	MpcGPKLeader = iota + 0
	MpcGPKPeer
	MpcSignLeader
	MpcSignPeer
)

const MaxMalice = 2

const (
	SK256Curve = iota + 0
	BN256Curve
)

const (
	StatusCode = iota + 10 // used by storeman protocol
	KeepaliveCode
	KeepaliveOkCode
	MPCError
	RequestMPC // ask for a new mpc Context
	MPCMessage // get a message for a Context
	RequestMPCNonce
	KeepaliveCycle
	CheckAllPeerConnected
	BuildStoremanGroup
	AllPeersInfo
	GetPeersInfo
	NumberOfMessageCodes
	//MPCTimeOut = time.Second * 100
	MPCTimeOut = time.Second * 5
	//MPCTimeOut = time.Second * 20
	PName   = "storeman"
	PVer    = uint64(10)
	PVerStr = "1.1"
)
const (
	MpcPrivateShare = "MpcPrivateShare" // skShare

	// R stage
	RSKSIJ     = "RSKSIJ"     // save sij with send index.
	RRcvedColl = "RRcvedColl" // scar number. received send index collection.(big.Int)

	RRcvedCollInter = "RRcvedCollInter" // received send index collection.(big.Int)

	RSkShare = "RSkShare" // rskShare   only self RSkShare
	RPkShare = "RPkShare" // rpkShare   rpkShare + "index" save rpkShare
	RPk      = "RPk"      // RPk

	MpcPublicShare = "MpcPublicShare" // pkShare

	MpcContextResult = "MpcContextResult" // The final result of the context.

	PublicKeyResult = "PublicKeyResult" // gpk

	MpcM = "MpcM" // M
	MpcS = "MpcS" // S: s

	MpcExt       = "MpcExtern"    // extern
	MpcByApprove = "MpcByApprove" // by approve
	MpcCurve     = "MpcCurve"     // by approve
	MpcGrpId     = "MpcGrpId"     // group ID

	MpcTxHash   = "MpcTxHash"
	MpcGpkBytes = "MpcGpkBytes"
	MPCAction   = "MPCAction"

	RPolyCMG = "MPCRPolyCommitG" // node0's comment : RPolyCMG + "0"
	// bytsvalue: polyValue values: sig of the polyValue
	RPolyCoff = "RPolyCoff"

	RSkErrNum   = "RSkErrNum"
	RSkErrInfos = "RSkErrInfos"

	SShareErrNum   = "SShareErrNum"
	SShareErrInfos = "SShareErrInfos"

	ROKIndex = "ROKIndex"
	RKOIndex = "RKOIndex"
	RNOIndex = "RNOIndex"

	SOKIndex = "SOKIndex"
	SKOIndex = "SKOIndex"
	SNOIndex = "SNOIndex"

	SSlshProof = "SSlshProof"
	RSlshProof = "RSlshProof"

	RSlshProofNum    = "RSlshProofNum"
	MPCSSlshProofNum = "MPCSSlshProofNum"
)

const (
	MpcApproving     = "MpcApproving"
	MpcApproved      = "MpcApproved"
	MpcApprovingKeys = "MpcApprovingKeys" // key : MpcApprovingKeys, value: array of the key of the data.
)

type PeerInfo struct {
	PeerID discover.NodeID
	Seed   uint64
}
type SliceStoremanGroup []discover.NodeID

func (s SliceStoremanGroup) Len() int {
	return len(s)
}
func (s SliceStoremanGroup) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SliceStoremanGroup) Less(i, j int) bool {
	return bytes.Compare(s[i][:], s[j][:]) < 0
}

type GetMessageInterface interface {
	HandleMessage(*StepMessage) bool
}

type StepMessage struct {
	MsgCode   uint64 //message code
	PeerID    *discover.NodeID
	Peers     *[]PeerInfo
	Data      []big.Int //message data
	BytesData [][]byte
	StepId    int
}

type MpcMessage struct {
	ContextID uint64
	StepID    uint64
	Peers     []byte
	Data      []big.Int //message data
	BytesData [][]byte
}
