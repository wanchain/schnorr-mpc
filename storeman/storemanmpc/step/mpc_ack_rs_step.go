package step

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type MpcAckRSStep struct {
	BaseStep
	message    map[discover.NodeID]bool
	remoteMpcR map[discover.NodeID][]big.Int // R
	remoteMpcS map[discover.NodeID]big.Int   // S
	accType    string
	mpcR       [2]big.Int
	mpcS       big.Int
}

func CreateAckMpcRSStep(peers *[]mpcprotocol.PeerInfo, accType string) *MpcAckRSStep {
	mpc := &MpcAckRSStep{
		*CreateBaseStep(peers, -1),
		make(map[discover.NodeID]bool),
		make(map[discover.NodeID][]big.Int),
		make(map[discover.NodeID]big.Int),
		accType,
		[2]big.Int{*big.NewInt(0), *big.NewInt(0)},
		*big.NewInt(0)}
	return mpc
}

func (mars *MpcAckRSStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("MpcAckRSStep.InitStep begin")
	value, err := result.GetValue(mpcprotocol.RPublicKeyResult)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::InitStep","ack mpc account step, init fail. err", err.Error())
		return err
	}
	mars.mpcR[0], mars.mpcR[1] = value[0], value[1]

	sValue, err := result.GetValue(mpcprotocol.MpcS)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::InitStep","ack mpc account step, init fail. err", err.Error())
		return err
	}
	mars.mpcS = sValue[0]
	return nil
}

func (mars *MpcAckRSStep) CreateMessage() []mpcprotocol.StepMessage {
	return []mpcprotocol.StepMessage{mpcprotocol.StepMessage{
		MsgCode:   mpcprotocol.MPCMessage,
		PeerID:    nil,
		Peers:     nil,
		Data:      []big.Int{mars.mpcS, mars.mpcR[0], mars.mpcR[1]},
		BytesData: nil}}
}

func (mars *MpcAckRSStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	log.SyslogInfo("MpcAckRSStep.FinishStep begin")
	err := mars.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	err = mars.verifyRS(result)
	if err != nil {
		return err
	}

	// rpk : R
	rpk := new(ecdsa.PublicKey)
	rpk.Curve = crypto.S256()
	rpk.X, rpk.Y = &mars.mpcR[0], &mars.mpcR[1]
	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	buffer.Write(crypto.FromECDSAPub(rpk))
	// S
	buffer.Write(mars.mpcS.Bytes())
	result.SetByteValue(mpcprotocol.MpcContextResult, buffer.Bytes())

	return nil
}

func (mars *MpcAckRSStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("MpcAckRSStep.HandleMessage begin")
	_, exist := mars.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcAckRSStep::HandleMessage","MpcAckRSStep.HandleMessage fail. peer doesn't exist in task peer group. peerID",
			msg.PeerID.String())
		return false
	}

	if len(msg.Data) >= 3 {
		mars.remoteMpcR[*msg.PeerID] = []big.Int{msg.Data[1], msg.Data[2]}
		mars.remoteMpcS[*msg.PeerID] = msg.Data[0]
	}

	mars.message[*msg.PeerID] = true
	return true
}

func (mars *MpcAckRSStep) verifyRS(result mpcprotocol.MpcResultInterface) error {
	// check R
	for _, mpcR := range mars.remoteMpcR {
		if mpcR == nil {
			return mpcprotocol.ErrInvalidMPCR
		}

		if mars.mpcR[0].Cmp(&mpcR[0]) != 0 || mars.mpcR[1].Cmp(&mpcR[1]) != 0 {
			return mpcprotocol.ErrInvalidMPCR
		}
	}
	// check S
	for _, mpcS := range mars.remoteMpcS {
		if mars.mpcS.Cmp(&mpcS) != 0 {
			return mpcprotocol.ErrInvalidMPCS
		}
	}

	// check signVerify
	M, err := result.GetByteValue(mpcprotocol.MpcM)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS","ack MpcAckRSStep get MpcM . err", err.Error())
		return err
	}

	//hashMBytes := crypto.Keccak256(M)
	hashMBytes := sha256.Sum256(M)

	// gpk
	gpkItem, err := result.GetValue(mpcprotocol.PublicKeyResult)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS","ack MpcAckRSStep get PublicKeyResult . err", err.Error())
		return err
	}
	gpk := new(ecdsa.PublicKey)
	gpk.Curve = crypto.S256()
	gpk.X, gpk.Y = &gpkItem[0], &gpkItem[1]

	// rpk : R
	rpk := new(ecdsa.PublicKey)
	rpk.Curve = crypto.S256()
	rpk.X, rpk.Y = &mars.mpcR[0], &mars.mpcR[1]

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	//buffer.Write(M[:])
	buffer.Write(hashMBytes[:])

	buffer.Write(crypto.FromECDSAPub(rpk))
	//mTemp := crypto.Keccak256(buffer.Bytes())
	mTemp := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mTemp[:])

	// check ssG = rpk + m*gpk
	ssG := new(ecdsa.PublicKey)
	ssG.Curve = crypto.S256()
	ssG.X, ssG.Y = crypto.S256().ScalarBaseMult(mars.mpcS.Bytes())

	// m*gpk
	mgpk := new(ecdsa.PublicKey)
	mgpk.Curve = crypto.S256()
	mgpk.X, mgpk.Y = crypto.S256().ScalarMult(gpk.X, gpk.Y, m.Bytes())

	// rpk + m*gpk
	temp := new(ecdsa.PublicKey)
	temp.Curve = crypto.S256()

	temp.X, temp.Y = crypto.S256().Add(mgpk.X, mgpk.Y, rpk.X, rpk.Y)

	log.Info("@@@@@@@@@@@@@@verifyRS@@@@@@@@@@@@@@",
		"M", hexutil.Encode(M[:]),
		"hash(M)", hexutil.Encode(hashMBytes[:]),
		"m", hexutil.Encode(m.Bytes()),
		"R", hexutil.Encode(crypto.FromECDSAPub(rpk)),
		"rpk+m*gpk", hexutil.Encode(crypto.FromECDSAPub(temp)),
		"sG", hexutil.Encode(crypto.FromECDSAPub(ssG)),
		"s", hexutil.Encode(mars.mpcS.Bytes()),
		"gpk", hexutil.Encode(crypto.FromECDSAPub(gpk)))

	if ssG.X.Cmp(temp.X) == 0 && ssG.Y.Cmp(temp.Y) == 0 {
		log.SyslogInfo("Verification success")
	} else {
		log.SyslogErr("Verification failed")
		return mpcprotocol.ErrVerifyFailed
	}
	return nil
}
