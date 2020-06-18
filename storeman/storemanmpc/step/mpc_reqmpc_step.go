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
	messageType      int64
	mpcSignByApprove []big.Int
	address          []byte
	mpcM             []byte
	mpcExt           []byte
	message          map[discover.NodeID]bool
	peerCount        uint16
}

func CreateRequestMpcStep(peers *[]mpcprotocol.PeerInfo, pc uint16, messageType int64) *RequestMpcStep {

	return &RequestMpcStep{
		BaseStep:    *CreateBaseStep(peers, len(*peers)-1),
		messageType: messageType,
		message:     make(map[discover.NodeID]bool),
		peerCount:   pc}
}

func (req *RequestMpcStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("RequestMpcStep.InitStep begin")
	req.BaseStep.InitStep(result)
	if req.messageType == mpcprotocol.MpcGPKLeader {
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

		for index, peer := range *req.peers {
			log.Info("RequestMpcStep::InitStep ",
				"index", index,
				"peerID", peer.PeerID.String(),
				"seed", peer.Seed)
		}

	} else if req.messageType == mpcprotocol.MpcSignLeader {

		var err error
		req.address, err = result.GetByteValue(mpcprotocol.MpcGpkBytes)
		if err != nil {
			return err
		}

		req.mpcM, err = result.GetByteValue(mpcprotocol.MpcM)
		if err != nil {
			return err
		}

		req.mpcExt, err = result.GetByteValue(mpcprotocol.MpcExt)
		if err != nil {
			return err
		}

		req.mpcSignByApprove, err = result.GetValue(mpcprotocol.MpcByApprove)
		if err != nil {
			return err
		}

	}

	return nil
}

func (req *RequestMpcStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("RequestMpcStep.CreateMessage.....")
	log.Info("RequestMpcStep", "CreateMessage peers", *req.peers)
	msg := mpcprotocol.StepMessage{
		MsgCode:   mpcprotocol.RequestMPC,
		PeerID:    nil,
		Peers:     req.peers,
		Data:      nil,
		BytesData: nil}

	msg.Data = make([]big.Int, 3)
	msg.Data[0].SetInt64(req.messageType)
	if req.messageType == mpcprotocol.MpcSignLeader {

		msg.Data[1] = req.mpcSignByApprove[0]
		msg.Data[2] = *big.NewInt(0).SetUint64(uint64(req.peerCount))

		msg.BytesData = make([][]byte, 3)
		msg.BytesData[0] = req.mpcM
		msg.BytesData[1] = req.address
		msg.BytesData[2] = req.mpcExt
	} else if req.messageType == mpcprotocol.MpcGPKLeader {
		//todo  do nothing?
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
	result.SetValue(mpcprotocol.MPCAction, data)
	return nil
}

func (req *RequestMpcStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("RequestMpcStep::HandleMessage", "RequestMpcStep.HandleMessage begin, peerID", msg.PeerID.String())
	_, exist := req.message[*msg.PeerID]
	if exist {
		log.SyslogErr("RequestMpcStep::HandleMessage", "RequestMpcStep.HandleMessage, get message from peerID fail. peer",
			msg.PeerID.String())
		return false
	}

	req.message[*msg.PeerID] = true
	return true
}
