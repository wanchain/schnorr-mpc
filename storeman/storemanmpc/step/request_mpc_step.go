package step

import (
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"math/rand"
	"time"
)

type RequestMpcStep struct {
	BaseStep
	messageType int64
	accType     []byte
	txHash      big.Int
	address     big.Int
	chainID     big.Int
	chainType   []byte
	signType    []byte
	txCode      []byte
	message     map[discover.NodeID]bool
	peerCount   uint16
}

func (req *RequestMpcStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("RequestMpcStep.InitStep begin")

	if req.messageType == mpcprotocol.MpcCreateLockAccountLeader {
		findMap := make(map[uint64]bool)
		rand.Seed(time.Now().UnixNano())
		for i := 0; i < len(*req.peers); i++ {
			for {
				(*req.peers)[i].Seed = (uint64)(rand.Intn(0x0FFFFFE) + 1)
				_, exist := findMap[(*req.peers)[i].Seed]
				if exist {
					continue
				}

				findMap[(*req.peers)[i].Seed] = true
				break
			}
		}

		accType, err := result.GetByteValue(mpcprotocol.MpcStmAccType)
		if err != nil {
			return err
		}

		req.accType = accType
		log.SyslogInfo("RequestMpcStep.InitStep, accType:%s", string(accType[:]))

	} else if req.messageType == mpcprotocol.MpcTXSignLeader {
		addr, err := result.GetValue(mpcprotocol.MpcAddress)
		if err != nil {
			return err
		}

		req.address = addr[0]
		req.chainType, err = result.GetByteValue(mpcprotocol.MpcChainType)
		if err != nil {
			return err
		}

		req.signType, err = result.GetByteValue(mpcprotocol.MpcSignType)
		if err != nil {
			return err
		}

		req.txCode, err = result.GetByteValue(mpcprotocol.MpcTransaction)
		if err != nil {
			return err
		}

		if string(req.chainType) != "BTC" {
			hash, err := result.GetValue(mpcprotocol.MpcTxHash + "_0")
			if err != nil {
				return err
			}

			req.txHash = hash[0]
			chainID, err := result.GetValue(mpcprotocol.MpcChainID)
			if err != nil {
				return err
			}

			req.chainID = chainID[0]
		}
	}

	return nil
}

func CreateRequestMpcStep(peers *[]mpcprotocol.PeerInfo, pc uint16, messageType int64) *RequestMpcStep {
	return &RequestMpcStep{BaseStep: *CreateBaseStep(peers, len(*peers)-1),
		messageType: messageType,
		message:     make(map[discover.NodeID]bool),
		peerCount:   pc}
}

func (req *RequestMpcStep) CreateMessage() []mpcprotocol.StepMessage {
	msg := mpcprotocol.StepMessage{
		MsgCode:   mpcprotocol.RequestMPC,
		PeerID:    nil,
		Peers:     req.peers,
		Data:      nil,
		BytesData: nil}
	msg.Data = make([]big.Int, 1)
	msg.Data[0].SetInt64(req.messageType)
	if req.messageType == mpcprotocol.MpcTXSignLeader {
		msg.Data = append(msg.Data, req.txHash)
		msg.Data = append(msg.Data, req.address)
		msg.Data = append(msg.Data, req.chainID)
		msg.Data = append(msg.Data, *big.NewInt(0).SetUint64(uint64(req.peerCount)))
		msg.BytesData = make([][]byte, 3)
		msg.BytesData[0] = req.chainType
		msg.BytesData[1] = req.txCode
		msg.BytesData[2] = req.signType
	} else if req.messageType == mpcprotocol.MpcCreateLockAccountLeader {
		msg.BytesData = make([][]byte, 1)
		msg.BytesData[0] = req.accType
	}

	return []mpcprotocol.StepMessage{msg}
}

func (req *RequestMpcStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := req.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	data := make([]big.Int, 1)
	data[0].SetInt64(req.messageType)
	result.SetValue(mpcprotocol.MPCActoin, data)

	if req.messageType == mpcprotocol.MpcTXSignLeader {

		rcvedCount := len(req.message)
		if rcvedCount < (mpcprotocol.MpcSchnrThr - 1) {
			log.SyslogErr("RequestMpcStep", "need number ", mpcprotocol.MpcSchnrThr, "received num", rcvedCount)

			mpcMsg := &mpcprotocol.MpcMessage{ContextID: req.mpcId,
				StepID: 0,
				Peers:  []byte(mpcprotocol.ErrFailedTxVerify.Error())}

			mpc.BoardcastMessage(nil, mpcprotocol.MPCError, mpcMsg)

			return mpcprotocol.ErrVerifyFailed
		}
	}
	return nil
}

func (req *RequestMpcStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("RequestMpcStep.HandleMessage begin, peerID:%s", msg.PeerID.String())
	_, exist := req.message[*msg.PeerID]
	if exist {
		log.SyslogErr("RequestMpcStep.HandleMessage, get message from peerID fail. peer:%s", msg.PeerID.String())
		return false
	}

	req.message[*msg.PeerID] = true
	return true
}
