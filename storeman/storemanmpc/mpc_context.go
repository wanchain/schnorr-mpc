package storemanmpc

import (
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"strconv"
	"sync"
)

type MemStatus struct {
	All  uint64 `json:"all"`
	Used uint64 `json:"used"`
	Free uint64 `json:"free"`
	Self uint64 `json:"self"`
}

const InternalErr = -1
const (
	success = iota
	rNW
	sNW
	rSlsh
	sSlsh
)

type MpcStepFunc interface {
	mpcprotocol.GetMessageInterface
	InitMessageLoop(mpcprotocol.GetMessageInterface) error
	Quit(error)
	InitStep(mpcprotocol.MpcResultInterface) error
	CreateMessage() []mpcprotocol.StepMessage
	FinishStep(mpcprotocol.MpcResultInterface, mpcprotocol.StoremanManager) error
	GetMessageChan() chan *mpcprotocol.StepMessage
	SetWaitAll(bool)
	SetWaiting(int)
	SetStepId(int)
}

type MpcContext struct {
	ContextID   uint64 //Unique id for every content
	quitMu      sync.Mutex
	bQuit       bool
	peers       []mpcprotocol.PeerInfo
	mpcResult   mpcprotocol.MpcResultInterface
	MpcSteps    []MpcStepFunc
	MapStepChan map[uint64]chan *mpcprotocol.StepMessage
}

func (mpcCtx *MpcContext) getMpcResult(err error) (interface{}, error) {

	sr := mpcprotocol.SignedResult{}
	mpcResult := mpcCtx.mpcResult

	if err == nil {
		sr.ResultType = success
		value, err := mpcCtx.mpcResult.GetByteValue(mpcprotocol.MpcContextResult)

		grpId, grpIdString, _ := osmconf.GetGrpId(mpcResult)

		log.SyslogInfo("getMpcResult", "grpIdString", grpIdString)

		okIndexes, _ := mpcResult.GetValue(mpcprotocol.SOKIndex)

		log.SyslogInfo("getMpcResult", "okIndexes", okIndexes)

		retBig, _ := osmconf.BuildDataByIndexes(&okIndexes)
		sr.IncntData = retBig.Bytes()
		log.SyslogInfo("getMpcResult", "IncntData", hexutil.Encode(sr.IncntData))

		if err != nil {
			return nil, err
		} else {
			sr.R = value[0:65]
			sr.S = value[65:]
			sr.GrpId = grpId

			//sr.IncntData
			return sr, nil
		}
	}

	if err != mpcprotocol.ErrRSlsh &&
		err != mpcprotocol.ErrSSlsh &&
		err != mpcprotocol.ErrRNW &&
		err != mpcprotocol.ErrSNW {
		return nil, err
	}

	if err == mpcprotocol.ErrRSlsh {
		//build R slash proof
		sr.ResultType = rSlsh

		keyErrNum := mpcprotocol.RSkErrNum
		errNum, _ := mpcResult.GetValue(keyErrNum)
		errNumInt64 := errNum[0].Int64()
		for i := 0; i < int(errNumInt64); i++ {
			key := mpcprotocol.RSlshProof + strconv.Itoa(int(i))
			rslshValue, err := mpcResult.GetValue(key)
			if err != nil {
				log.SyslogErr("getMpcResult", "mpcResult.GetValue error:", err.Error())
				return nil, err
			}

			if len(rslshValue) != 9 {
				log.SyslogErr("getMpcResult rslshValue format error.", "len(rslshValue)", len(rslshValue))
				return nil, err
			} else {

				oneRPrf := mpcprotocol.RSlshPrf{}
				oneRPrf.PolyCMR = rslshValue[1].Bytes()
				oneRPrf.PolyCMS = rslshValue[2].Bytes()
				oneRPrf.PolyData = rslshValue[3].Bytes()
				oneRPrf.PolyDataR = rslshValue[4].Bytes()
				oneRPrf.PolyDataS = rslshValue[5].Bytes()
				oneRPrf.SndrAndRcvrIndex = [2]uint8{uint8(rslshValue[6].Int64()), uint8(rslshValue[7].Int64())}

				if rslshValue[0].Cmp(schnorrmpc.BigZero) == 0 {
					oneRPrf.BecauseSndr = false
				} else {
					oneRPrf.BecauseSndr = true
				}

				polyLen := int(rslshValue[8].Int64())

				rslshBytes, err := mpcResult.GetByteValue(key)
				if err != nil {
					log.SyslogErr("getMpcResult", "GetByteValue error,key", key, "error", err.Error())
					return nil, err
				}
				oneRPrf.PolyCM = rslshBytes[0 : 65*polyLen]
				sr.GrpId = rslshBytes[65*polyLen:]

				sr.RSlsh = append(sr.RSlsh, oneRPrf)
			}

		}
		return sr, err
	}
	if err == mpcprotocol.ErrSSlsh {
		// build S slash proof
		sr.ResultType = sSlsh

		keyErrNum := mpcprotocol.SShareErrNum
		errNum, _ := mpcResult.GetValue(keyErrNum)
		errNumInt64 := errNum[0].Int64()
		for i := 0; i < int(errNumInt64); i++ {
			key := mpcprotocol.SSlshProof + strconv.Itoa(int(i))
			sslshValue, _ := mpcResult.GetValue(key)

			if len(sslshValue) != 8 {
				log.SyslogErr("getMpcResult sslsh format error.", "len(sslshValue)", len(sslshValue))
				return nil, err
			} else {

				oneRPrf := mpcprotocol.SSlshPrf{}
				oneRPrf.M = sslshValue[1].Bytes()
				oneRPrf.PolyData = sslshValue[2].Bytes()
				oneRPrf.PolyDataR = sslshValue[3].Bytes()
				oneRPrf.PolyDataS = sslshValue[4].Bytes()

				oneRPrf.SndrAndRcvrIndex = [2]uint8{uint8(sslshValue[5].Int64()), uint8(sslshValue[6].Int64())}

				if sslshValue[0].Cmp(schnorrmpc.BigZero) == 0 {
					oneRPrf.BecauseSndr = false
				} else {
					oneRPrf.BecauseSndr = true
				}

				rslshBytes, _ := mpcResult.GetByteValue(key)
				if err != nil {
					log.SyslogErr("getMpcResult", "GetByteValue error,key", key, "error", err.Error())
					return nil, err
				}

				oneRPrf.RPKShare = rslshBytes[0:65]
				oneRPrf.GPKShare = rslshBytes[65 : 65*2]
				sr.GrpId = rslshBytes[65*2:]

				sr.SSlsh = append(sr.SSlsh, oneRPrf)
			}

		}
		return sr, err
	}

	if err == mpcprotocol.ErrRNW {
		sr.ResultType = rNW
		grpId, grpIdString, _ := osmconf.GetGrpId(mpcResult)
		log.SyslogInfo("getMpcResult", "grpIdString", grpIdString)

		RNOIndex, _ := mpcResult.GetValue(mpcprotocol.RNOIndex)

		log.SyslogInfo("getMpcResult", "RNOIndex", RNOIndex)

		retBig, _ := osmconf.BuildDataByIndexes(&RNOIndex)
		sr.RNW = retBig.Bytes()
		sr.GrpId = grpId

		log.SyslogInfo("getMpcResult", "RNW", hexutil.Encode(sr.RNW))

		return sr, nil
	}

	if err == mpcprotocol.ErrSNW {
		sr.ResultType = sNW

		grpId, grpIdString, _ := osmconf.GetGrpId(mpcResult)
		log.SyslogInfo("getMpcResult", "grpIdString", grpIdString)

		SNOIndex, _ := mpcResult.GetValue(mpcprotocol.SNOIndex)

		log.SyslogInfo("getMpcResult", "SNOIndex", SNOIndex)

		retBig, _ := osmconf.BuildDataByIndexes(&SNOIndex)
		sr.SNW = retBig.Bytes()
		sr.GrpId = grpId

		log.SyslogInfo("getMpcResult", "SNW", hexutil.Encode(sr.IncntData))

		return sr, nil
	}

	return nil, nil
}

func (mpcCtx *MpcContext) getMessage(PeerID *discover.NodeID,
	msg *mpcprotocol.MpcMessage,
	peers *[]mpcprotocol.PeerInfo) error {

	mpcCtx.MapStepChan[msg.StepID] <- &mpcprotocol.StepMessage{MsgCode: 0,
		PeerID:    PeerID,
		Peers:     peers,
		Data:      msg.Data,
		BytesData: msg.BytesData,
		StepId:    int(msg.StepID)}
	return nil
}

func createMpcContext(contextID uint64,
	peers []mpcprotocol.PeerInfo,
	mpcResult mpcprotocol.MpcResultInterface) *MpcContext {

	mpc := &MpcContext{
		ContextID:   contextID,
		peers:       peers,
		bQuit:       false,
		quitMu:      sync.Mutex{},
		mpcResult:   mpcResult,
		MapStepChan: make(map[uint64]chan *mpcprotocol.StepMessage),
	}

	return mpc
}

func (mpcCtx *MpcContext) setMpcStep(mpcSteps ...MpcStepFunc) {
	mpcCtx.MpcSteps = mpcSteps
	for i, step := range mpcSteps {
		mpcCtx.MapStepChan[uint64(i)] = step.GetMessageChan()
	}
}

func (mpcCtx *MpcContext) quit(err error) {
	if err == nil {
		log.SyslogInfo("MpcContext.quit")
	} else {
		log.SyslogErr("MpcContext.quit", "err", err.Error())
	}

	mpcCtx.quitMu.Lock()
	defer mpcCtx.quitMu.Unlock()
	if mpcCtx.bQuit {
		return
	}
	mpcCtx.bQuit = true
	for i := 0; i < len(mpcCtx.MpcSteps); i++ {
		mpcCtx.MpcSteps[i].Quit(err)
	}
}

func (mpcCtx *MpcContext) mainMPCProcess(StoremanManager mpcprotocol.StoremanManager) error {
	log.SyslogInfo("mainMPCProcess begin", "ctxid", mpcCtx.ContextID)
	mpcErr := error(nil)
	//for _, mpcCt := range mpcCtx.MpcSteps {
	//	err := mpcCt.InitMessageLoop(mpcCt)
	//	if err != nil {
	//		mpcErr = err
	//		break
	//	}
	//}

	peerIDs := make([]discover.NodeID, 0)
	for _, item := range mpcCtx.peers {
		peerIDs = append(peerIDs, item.PeerID)
	}

	if mpcErr == nil {
		// todo need think over
		//mpcCtx.mpcResult.Initialize()
		for i := 0; i < len(mpcCtx.MpcSteps); i++ {
			err := mpcCtx.MpcSteps[i].InitStep(mpcCtx.mpcResult)
			if err != nil {
				mpcErr = err
				break
			}

			// todo need think over. should initmessageLoop here or above??
			err = mpcCtx.MpcSteps[i].InitMessageLoop(mpcCtx.MpcSteps[i])
			if err != nil {
				mpcErr = err
				break
			}
			log.SyslogInfo("\n")
			log.SyslogInfo("===============================Start============================================")
			log.SyslogInfo("\n")

			log.SyslogInfo("--------step init finished--------", "ctxid", mpcCtx.ContextID, "stepId", i)
			msg := mpcCtx.MpcSteps[i].CreateMessage()
			if msg != nil {
				for _, item := range msg {
					mpcMsg := &mpcprotocol.MpcMessage{ContextID: mpcCtx.ContextID,
						StepID:    uint64(i),
						Data:      item.Data,
						BytesData: item.BytesData}
					//StoremanManager.SetMessagePeers(mpcMsg, item.Peers)
					if item.PeerID != nil {
						StoremanManager.P2pMessage(item.PeerID, item.MsgCode, mpcMsg)
						log.SyslogInfo("step send a p2p msg", "ctxid", mpcCtx.ContextID, "stepId", i)
					} else {

						for _, item := range peerIDs {
							log.SyslogInfo("step boardcast a p2p msg", "peerid", item.String())
						}

						StoremanManager.BroadcastMessage(peerIDs, item.MsgCode, mpcMsg)
						log.SyslogInfo("step boardcast a p2p msg", "ctxid", mpcCtx.ContextID, "stepId", i)
					}
				}
			}

			log.SyslogInfo("step send p2p msg finished", "ctxid", mpcCtx.ContextID, "stepId", i)
			err = mpcCtx.MpcSteps[i].FinishStep(mpcCtx.mpcResult, StoremanManager)
			if err != nil {
				mpcErr = err
				break
			}

			log.SyslogInfo("--------step mssage finished--------", "ctxid", mpcCtx.ContextID, "stepId", i)

			log.SyslogInfo("\n")
			log.SyslogInfo("==============================End=============================================")
			log.SyslogInfo("\n")
		}
	}

	if mpcErr != nil {
		log.SyslogErr("mainMPCProcess fail", "err", mpcErr.Error())
		mpcMsg := &mpcprotocol.MpcMessage{ContextID: mpcCtx.ContextID,
			StepID: 0,
			Peers:  []byte(mpcErr.Error())}

		_, grpIdString, _ := osmconf.GetGrpId(mpcCtx.mpcResult)
		isLeader, _ := osmconf.GetOsmConf().IsLeader(grpIdString)
		if isLeader {
			StoremanManager.BroadcastMessage(peerIDs, mpcprotocol.MPCError, mpcMsg)
		}
	}

	mpcCtx.quit(nil)
	log.SyslogInfo("MpcContext finished", "ctx ID", mpcCtx.ContextID)
	return mpcErr
}
