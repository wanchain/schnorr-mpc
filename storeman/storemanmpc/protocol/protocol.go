package protocol

import (
	"bytes"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"math/big"
	"strconv"
	"time"
)

var (
	MpcSchnrThr        = 26 // MpcSchnrThr >= number(storeman )/2 +1
	MPCDegree          = MpcSchnrThr - 1
	MpcSchnrNodeNumber = 50 // At least MpcSchnrNodeNumber MPC nodes
)

const (
	MpcGPKLeader = iota + 0
	MpcGPKPeer
	MpcSignLeader
	MpcSignPeer
)

const (
	MpcCreateLockAccountLeader = iota + 0
	MpcCreateLockAccountPeer
	MpcTXSignLeader
	MpcTXSignPeer
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
	MPCTimeOut = time.Second * 100
	PName      = "storeman"
	PVer       = uint64(505)
	PVerStr    = "5.0.5"
)

const (
	MpcPrivateShare  = "MpcPrivateShare"
	MpcPrivateKey    = "MpcPrivateKey"
	MpcPublicShare   = "MpcPublicShare"
	MpcSignA         = "MpcSignA"
	MpcSignA0        = "MpcSignA0"
	MpcSignR         = "MpcSignR"
	MpcSignR0        = "MpcSignR0"
	MpcSignB         = "MpcSignB"
	MpcSignC         = "MpcSignC"
	MpcSignARSeed    = "MpcSignARSeed"
	MpcSignARResult  = "MpcSignARResult"
	MpcTxSignSeed    = "MpcTxSignSeed"
	MpcTxSignResultR = "MpcTxSignResultR"
	MpcTxSignResultV = "MpcTxSignResultV"
	MpcTxSignResult  = "MpcTxSignResult"
	MpcContextResult = "MpcContextResult"

	PublicKeyResult = "PublicKeyResult"
	MpcSignAPoint   = "MpcSignAPoint"
	MpcTxHash       = "MpcTxHash"
	MpcTransaction  = "MpcTransaction"
	MpcChainType    = "MpcChainType"
	MpcSignType     = "MpcSignType"
	MpcChainID      = "MpcChainID"
	MpcAddress      = "MpcAddress"
	MPCActoin       = "MPCActoin"
	MPCSignedFrom   = "MPCSignedFrom"
	MpcStmAccType   = "MpcStmAccType"
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

func CheckAccountType(accType string) bool {
	if accType == "WAN" || accType == "ETH" || accType == "BTC" {
		return true
	}

	return false
}

func GetPreSetKeyArr(keySeed string, num int) []string {
	keyArr := []string{}
	for i := 0; i < num; i++ {
		keyArr = append(keyArr, keySeed+"_"+strconv.Itoa(i))
	}

	return keyArr
}
