package step

import (
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"time"
)

type BaseStep struct {
	peers        *[]mpcprotocol.PeerInfo
	msgChan      chan *mpcprotocol.StepMessage
	finish       chan error
	waiting      int
	waitAll      bool // true: wait all
	stepId       int
	notRecvPeers map[discover.NodeID]*discover.NodeID
	mpcResult    mpcprotocol.MpcResultInterface
	schnorrMpcer mpcprotocol.SchnorrMPCer
}

func (step *BaseStep) InitStep(mpcResult mpcprotocol.MpcResultInterface) error {
	step.mpcResult = mpcResult
	return nil
}

func CreateBaseStep(peers *[]mpcprotocol.PeerInfo, wait int) *BaseStep {
	step := &BaseStep{
		peers:   peers,
		msgChan: make(chan *mpcprotocol.StepMessage, len(*peers)+3),
		finish:  make(chan error, 3)}

	if wait >= 0 {
		step.waiting = wait
	} else {
		step.waiting = len(*peers)
	}
	step.waitAll = true

	step.notRecvPeers = make(map[discover.NodeID]*discover.NodeID)
	for _, peer := range *peers {
		step.notRecvPeers[peer.PeerID] = &peer.PeerID
	}

	return step
}

func (step *BaseStep) InitMessageLoop(msger mpcprotocol.GetMessageInterface) error {
	log.SyslogInfo("BaseStep.InitMessageLoop begin")
	if step.waiting <= 0 {
		step.finish <- nil
	} else {
		go func() {
			log.SyslogInfo("InitMessageLoop begin")

			for {
				err := step.HandleMessage(msger)
				if err != nil {
					if err != mpcprotocol.ErrQuit {
						log.SyslogErr("BaseStep::InitMessageLoop", "InitMessageLoop fail, get message err, err", err.Error())
					}

					break
				}
			}
		}()
	}

	return nil
}

func (step *BaseStep) Quit(err error) {
	step.msgChan <- nil
	step.finish <- err
}

func (step *BaseStep) FinishStep() error {
	select {
	case err := <-step.finish:
		if err != nil {
			log.SyslogErr("BaseStep::FinishStep", " get a step finish error. err", err.Error())
		}

		step.msgChan <- nil
		return err
	case <-time.After(mpcprotocol.MPCTimeOut):
		log.SyslogWarning("BaseStep.FinishStep, wait step finish timeout")
		step.msgChan <- nil

		if !step.waitAll {
			return nil
		}
		return mpcprotocol.ErrTimeOut
	}
}

func (step *BaseStep) GetMessageChan() chan *mpcprotocol.StepMessage {
	return step.msgChan
}

func (step *BaseStep) HandleMessage(msger mpcprotocol.GetMessageInterface) error {
	var msg *mpcprotocol.StepMessage
	select {
	case msg = <-step.msgChan:
		if msg == nil {
			log.SyslogInfo("BaseStep get a quit msg")
			return mpcprotocol.ErrQuit
		}

		if msg.StepId != step.GetStepId() {
			log.SyslogErr("Get message is not in the right steps",
				"should step", step.stepId,
				"receive step", msg.StepId)
		} else {
			if step.waiting > 0 && msger.HandleMessage(msg) {

				delete(step.notRecvPeers, *msg.PeerID)

				step.waiting--
				if step.waiting <= 0 {
					step.finish <- nil
				}
			}
		}
	}

	return nil
}

func (step *BaseStep) getPeerIndex(peerID *discover.NodeID) int {
	for i, item := range *step.peers {
		if item.PeerID == *peerID {
			return i
		}
	}

	return -1
}

func (step *BaseStep) getPeerSeed(peerID *discover.NodeID) uint64 {
	for _, item := range *step.peers {
		if item.PeerID == *peerID {
			return item.Seed
		}
	}

	return 0
}

func (step *BaseStep) SetWaitAll(waitAll bool) {
	step.waitAll = waitAll
}

func (step *BaseStep) SetWaiting(waiting int) {
	step.waiting = waiting
}

func (step *BaseStep) SetStepId(stepId int) {
	step.stepId = stepId
}

func (step *BaseStep) GetStepId() int {
	return step.stepId
}

func (step *BaseStep) SetSchnorrMpcer(smcer mpcprotocol.SchnorrMPCer) {
	step.schnorrMpcer = smcer
}

func (step *BaseStep) SchnorrMpcer() mpcprotocol.SchnorrMPCer {
	return step.schnorrMpcer
}

func (step *BaseStep) GetMsgGens() []MpcMessageGenerator {
	return nil
}
