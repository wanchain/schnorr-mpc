package step

import (
	"bytes"
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
)

type MpcAckRSStep struct {
	BaseStep
	message    map[discover.NodeID]bool
	remoteMpcR map[discover.NodeID]mpcprotocol.CurvePointer // R
	remoteMpcS map[discover.NodeID]big.Int                  // S
	accType    string
	//mpcR       [2]big.Int
	mpcR mpcprotocol.CurvePointer
	mpcS big.Int
}

func CreateAckMpcRSStep(peers *[]mpcprotocol.PeerInfo, accType string) *MpcAckRSStep {
	mpc := &MpcAckRSStep{
		*CreateBaseStep(peers, -1),
		make(map[discover.NodeID]bool),
		make(map[discover.NodeID]mpcprotocol.CurvePointer),
		make(map[discover.NodeID]big.Int),
		accType,
		[2]big.Int{*big.NewInt(0), *big.NewInt(0)},
		*big.NewInt(0)}
	return mpc
}

func (mars *MpcAckRSStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("MpcAckRSStep.InitStep begin")
	mars.BaseStep.InitStep(result)
	rpkBytes, err := result.GetByteValue(mpcprotocol.RPk)
	mars.mpcR, err = mars.schnorrMpcer.UnMarshPt(rpkBytes)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::InitStep", "ack mpc account step, init fail UnMarshPt. err", err.Error())
		return err
	}

	sValue, err := result.GetValue(mpcprotocol.MpcS)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::InitStep", "ack mpc account step, init fail. err", err.Error())
		return err
	}
	mars.mpcS = sValue[0]
	return nil
}

func (mars *MpcAckRSStep) CreateMessage() []mpcprotocol.StepMessage {

	rpkBytes, err := mars.schnorrMpcer.MarshPt(mars.mpcR)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::InitStep", "ack mpc account step, init fail. err", err.Error())
	}

	msg := mpcprotocol.StepMessage{
		MsgCode:   mpcprotocol.MPCMessage,
		PeerID:    nil,
		Peers:     nil,
		Data:      nil,
		BytesData: nil}
	msg.BytesData = make([][]byte, 1)
	msg.BytesData[0] = rpkBytes

	msg.Data = make([]big.Int, 1)
	msg.Data[0] = mars.mpcS

	return []mpcprotocol.StepMessage{msg}
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
	rpkBytes, err := mars.schnorrMpcer.MarshPt(mars.mpcR)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	buffer.Write(rpkBytes)
	// S
	buffer.Write(mars.mpcS.Bytes())
	result.SetByteValue(mpcprotocol.MpcContextResult, buffer.Bytes())

	return nil
}

func (mars *MpcAckRSStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("MpcAckRSStep.HandleMessage begin")
	_, exist := mars.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcAckRSStep::HandleMessage", "MpcAckRSStep.HandleMessage fail. peer doesn't exist in task peer group. peerID",
			msg.PeerID.String())
		return false
	}

	if len(msg.Data) >= 1 {
		mars.remoteMpcS[*msg.PeerID] = msg.Data[0]
	}

	if len(msg.BytesData) >= 1 {
		rpt, err := mars.schnorrMpcer.UnMarshPt(msg.BytesData[0])
		if err != nil {
			log.SyslogErr("MpcAckRSStep::HandleMessage", "MpcAckRSStep.HandleMessage UnMarshPt error", err.Error())
			return false
		}
		mars.remoteMpcR[*msg.PeerID] = rpt
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

		if !mars.schnorrMpcer.Equal(mars.mpcR, mpcR) {
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
		log.SyslogErr("MpcAckRSStep::verifyRS", "ack MpcAckRSStep get MpcM . err", err.Error())
		return err
	}

	//hashMBytes := crypto.Keccak256(M)
	hashMBytes := sha256.Sum256(M)

	// gpk
	gpkItem, err := result.GetByteValue(mpcprotocol.MpcGpkBytes)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "ack MpcAckRSStep get PublicKeyResult . err", err.Error())
		return err
	}

	smpcer := mars.schnorrMpcer
	gpk, err := smpcer.UnMarshPt(gpkItem[:])
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "UnMarshPt err", err.Error())
		return err
	}

	// rpk : R
	rpkBytes, err := smpcer.MarshPt(mars.mpcR)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "MarshPt err", err.Error())
		return err
	}
	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	//buffer.Write(M[:])
	buffer.Write(hashMBytes[:])
	buffer.Write(rpkBytes)
	mTemp := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mTemp[:])
	m = m.Mod(m, smpcer.GetMod())
	// check ssG = rpk + m*gpk
	ssG, err := smpcer.SkG(&mars.mpcS)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "SkG err", err.Error())
		return err
	}
	// m*gpk

	mgpk, err := smpcer.MulPK(m, gpk)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "MulPK err", err.Error())
		return err
	}
	//// rpk + m*gpk
	temp, err := smpcer.Add(mgpk, mars.mpcR)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS", "Add err", err.Error())
		return err
	}
	log.Info("@@@@@@@@@@@@@@verifyRS@@@@@@@@@@@@@@",
		"M", hexutil.Encode(M[:]),
		"hash(M)", hexutil.Encode(hashMBytes[:]),
		"m", hexutil.Encode(m.Bytes()),
		"R", hexutil.Encode(rpkBytes),
		"rpk+m*gpk", smpcer.PtToHexString(temp),
		"sG", smpcer.PtToHexString(ssG),
		"s", hexutil.Encode(mars.mpcS.Bytes()),
		"gpk", smpcer.PtToHexString(gpk))

	if smpcer.Equal(ssG, temp) {
		log.SyslogInfo("Verification success")
	} else {
		log.SyslogErr("Verification failed")
		return mpcprotocol.ErrVerifyFailed
	}

	return nil
}
