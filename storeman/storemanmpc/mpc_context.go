package storemanmpc

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpcbn"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"github.com/wanchain/schnorr-mpc/storeman/storemanmpc/step"
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
	SetSchnorrMpcer(mpcprotocol.SchnorrMPCer)
	GetMsgGens() []step.MpcMessageGenerator
}

type MpcContext struct {
	ContextID    uint64 //Unique id for every content
	quitMu       sync.Mutex
	bQuit        bool
	peers        []mpcprotocol.PeerInfo
	mpcResult    mpcprotocol.MpcResultInterface
	MpcSteps     []MpcStepFunc
	MapStepChan  map[uint64]chan *mpcprotocol.StepMessage
	schnorrMPCer mpcprotocol.SchnorrMPCer
	curveType    uint8
}

func (mpcCtx *MpcContext) buildSucc(sr *mpcprotocol.SignedResult) (interface{}, error) {
	mpcResult := mpcCtx.mpcResult
	sr.ResultType = success
	value, err := mpcCtx.mpcResult.GetByteValue(mpcprotocol.MpcContextResult)
	grpId, grpIdString, _ := osmconf.GetGrpId(mpcResult)

	log.SyslogInfo("buildSuccSR.getMpcResult", "grpIdString", grpIdString)

	okIndexes, _ := mpcResult.GetValue(mpcprotocol.SOKIndex)

	OkIndexesStr, _ := osmconf.BuildStrByIndexes(&okIndexes)
	log.SyslogInfo("buildSuccSR.getMpcResult", "okIndexes", OkIndexesStr)

	retBig, _ := osmconf.BuildDataByIndexes(&okIndexes)
	sr.IncntData = retBig.Bytes()
	log.SyslogInfo("buildSuccSR.getMpcResult", "IncntData", hexutil.Encode(sr.IncntData))

	var smpcer mpcprotocol.SchnorrMPCer
	switch int(mpcCtx.curveType) {
	case mpcprotocol.SK256Curve:
		smpcer = schnorrmpc.NewSkSchnorrMpc()
	case mpcprotocol.BN256Curve:
		smpcer = schnorrmpcbn.NewBnSchnorrMpc()
	default:
		smpcer = schnorrmpc.NewSkSchnorrMpc()
	}
	if err != nil {
		return nil, err
	} else {
		sr.R = value[0:smpcer.PtByteLen()]
		sr.S = value[smpcer.PtByteLen():]
		sr.GrpId = grpId

		return *sr, nil
	}
}

func (mpcCtx *MpcContext) buildRSlsh(sr *mpcprotocol.SignedResult) (interface{}, error) {
	mpcResult := mpcCtx.mpcResult
	//build R slash proof
	sr.ResultType = rSlsh

	keyErrNum := mpcprotocol.RSlshProofNum
	errNum, err := mpcResult.GetValue(keyErrNum)
	if err != nil {
		log.SyslogErr("getMpcResult", "RSlshProofNum mpcResult.GetValue error:", err.Error(), "key", keyErrNum)
		return nil, err
	}
	errNumInt64 := errNum[0].Int64()
	for i := 0; i < int(errNumInt64); i++ {
		key := mpcprotocol.RSlshProof + strconv.Itoa(int(i))
		rslshValue, err := mpcResult.GetValue(key)
		if err != nil {
			log.SyslogErr("getMpcResult", "RSlshProof mpcResult.GetValue error:", err.Error())
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

			if rslshValue[0].Cmp(schcomm.BigZero) == 0 {
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
			//oneRPrf.PolyCM = rslshBytes[0 : 65*polyLen]
			//sr.GrpId = rslshBytes[65*polyLen:]

			ptLen := mpcCtx.schnorrMPCer.PtByteLen()
			oneRPrf.PolyCM = mpcCtx.trip04forPts(rslshBytes[0:ptLen*polyLen], ptLen)
			sr.GrpId = rslshBytes[ptLen*polyLen:]

			sr.RSlsh = append(sr.RSlsh, oneRPrf)
		}

	}
	return sr, nil

}

func (mpcCtx *MpcContext) trip04forPts(b hexutil.Bytes, ptLen int) hexutil.Bytes {
	CommonPKLength := 64
	if ptLen == CommonPKLength {
		return b
	}
	count := len(b) / ptLen
	log.SyslogDebug("MpcContext.trip04forPts", "b", hexutil.Encode(b), "count", count, "ptLen", ptLen)
	var ret bytes.Buffer
	for i := 0; i < count; i++ {
		onePtBytes := b[i*ptLen : (i+1)*ptLen]
		log.SyslogDebug("MpcContext.trip04forPts", "onePtBytes", hexutil.Encode(onePtBytes), "ptLen", ptLen, "CommonPKLength", CommonPKLength)
		ret.Write(onePtBytes[ptLen-CommonPKLength:])
	}
	return ret.Bytes()
}

func (mpcCtx *MpcContext) buildSSlsh(sr *mpcprotocol.SignedResult) (interface{}, error) {
	mpcResult := mpcCtx.mpcResult
	// build S slash proof
	sr.ResultType = sSlsh

	keyErrNum := mpcprotocol.MPCSSlshProofNum
	errNum, _ := mpcResult.GetValue(keyErrNum)
	errNumInt64 := errNum[0].Int64()
	for i := 0; i < int(errNumInt64); i++ {
		key := mpcprotocol.SSlshProof + strconv.Itoa(int(i))
		sslshValue, err := mpcResult.GetValue(key)
		if err != nil {
			log.SyslogErr("buildSSlsh mpcResult.GetValue", "key", key, "err", err.Error())
			return nil, err
		}
		if len(sslshValue) != 7 {
			log.SyslogErr("getMpcResult sslsh format error.", "len(sslshValue)", len(sslshValue))
			return nil, errors.New("getMpcResult sslsh format error")
		} else {

			oneRPrf := mpcprotocol.SSlshPrf{}
			oneRPrf.M = sslshValue[1].Bytes()
			oneRPrf.PolyData = sslshValue[2].Bytes()
			oneRPrf.PolyDataR = sslshValue[3].Bytes()
			oneRPrf.PolyDataS = sslshValue[4].Bytes()

			oneRPrf.SndrAndRcvrIndex = [2]uint8{uint8(sslshValue[5].Int64()), uint8(sslshValue[6].Int64())}

			if sslshValue[0].Cmp(schcomm.BigZero) == 0 {
				oneRPrf.BecauseSndr = false
			} else {
				oneRPrf.BecauseSndr = true
			}

			rslshBytes, err := mpcResult.GetByteValue(key)
			if err != nil {
				log.SyslogErr("getMpcResult", "GetByteValue error,key", key, "error", err.Error())
				return nil, err
			}

			//oneRPrf.RPKShare = rslshBytes[0:65]
			//oneRPrf.GPKShare = rslshBytes[65 : 65*2]
			//sr.GrpId = rslshBytes[65*2:]
			ptLen := mpcCtx.schnorrMPCer.PtByteLen()
			oneRPrf.RPKShare = mpcCtx.trip04forPts(rslshBytes[0:ptLen], ptLen)
			oneRPrf.GPKShare = mpcCtx.trip04forPts(rslshBytes[ptLen:ptLen*2], ptLen)
			sr.GrpId = rslshBytes[ptLen*2:]

			sr.SSlsh = append(sr.SSlsh, oneRPrf)

			log.SyslogInfo("...........................................getMpcResult", "oneSPrf", oneRPrf)
		}

	}
	fmt.Printf("getMpcResult%#v", sr)
	log.SyslogInfo("getMpcResult", " sr", sr)

	return sr, nil
}

func (mpcCtx *MpcContext) buildRNW(sr *mpcprotocol.SignedResult) (interface{}, error) {
	sr.ResultType = rNW
	mpcResult := mpcCtx.mpcResult
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

func (mpcCtx *MpcContext) buildSNW(sr *mpcprotocol.SignedResult) (interface{}, error) {
	sr.ResultType = sNW
	mpcResult := mpcCtx.mpcResult
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

func (mpcCtx *MpcContext) buildNormalErr(err error) (interface{}, error) {
	return nil, err
}

func (mpcCtx *MpcContext) getMpcResult(err error) (interface{}, error) {

	sr := mpcprotocol.SignedResult{}
	sr.CurveType = mpcCtx.curveType

	if err == nil {
		return mpcCtx.buildSucc(&sr)
	}

	if err == mpcprotocol.ErrRSlsh {
		return mpcCtx.buildRSlsh(&sr)
	}

	if err == mpcprotocol.ErrSSlsh {
		return mpcCtx.buildSSlsh(&sr)
	}

	if err == mpcprotocol.ErrRNW {
		return mpcCtx.buildRNW(&sr)
	}

	if err == mpcprotocol.ErrSNW {
		return mpcCtx.buildSNW(&sr)
	}

	return mpcCtx.buildNormalErr(err)
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
	mpcResult mpcprotocol.MpcResultInterface,
	curveType uint8) *MpcContext {

	mpc := &MpcContext{
		ContextID:   contextID,
		peers:       peers,
		bQuit:       false,
		quitMu:      sync.Mutex{},
		mpcResult:   mpcResult,
		MapStepChan: make(map[uint64]chan *mpcprotocol.StepMessage),
		curveType:   curveType,
	}

	switch int(curveType) {
	case mpcprotocol.SK256Curve:
		mpc.schnorrMPCer = schnorrmpc.NewSkSchnorrMpc()
	case mpcprotocol.BN256Curve:
		mpc.schnorrMPCer = schnorrmpcbn.NewBnSchnorrMpc()
	default:
		mpc.schnorrMPCer = schnorrmpc.NewSkSchnorrMpc()
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

	peerIDs := make([]discover.NodeID, 0)
	for _, item := range mpcCtx.peers {
		peerIDs = append(peerIDs, item.PeerID)
	}

	if mpcErr == nil {

		for i := 0; i < len(mpcCtx.MpcSteps); i++ {
			err := mpcCtx.MpcSteps[i].InitStep(mpcCtx.mpcResult)
			if err != nil {
				mpcErr = err
				break
			}

			err = mpcCtx.MpcSteps[i].InitMessageLoop(mpcCtx.MpcSteps[i])
			if err != nil {
				mpcErr = err
				break
			}
			log.Info("\n")
			log.SyslogInfo("------------------------------Start------------------------------", "stepId", i, "ctxid", mpcCtx.ContextID)
			log.Info("\n")

			msg := mpcCtx.MpcSteps[i].CreateMessage()
			if msg != nil {
				for _, item := range msg {
					mpcMsg := &mpcprotocol.MpcMessage{ContextID: mpcCtx.ContextID,
						StepID:    uint64(i),
						Data:      item.Data,
						BytesData: item.BytesData}
					if item.PeerID != nil {
						StoremanManager.P2pMessage(item.PeerID, item.MsgCode, mpcMsg)
						log.SyslogDebug("step send a p2p msg", "ctxid", mpcCtx.ContextID, "stepId", i)
					} else {

						for _, item := range peerIDs {
							log.Trace("step boardcast a p2p msg", "peerid", item.String())
						}

						StoremanManager.BroadcastMessage(peerIDs, item.MsgCode, mpcMsg)
						log.Trace("step boardcast a p2p msg", "ctxid", mpcCtx.ContextID, "stepId", i)
					}
				}
			}

			log.SyslogInfo("step send p2p msg finished", "ctxid", mpcCtx.ContextID, "stepId", i)
			err = mpcCtx.MpcSteps[i].FinishStep(mpcCtx.mpcResult, StoremanManager)
			if err != nil {
				mpcErr = err
				break
			}

			log.Info("\n")
			log.SyslogInfo("------------------------------End------------------------------", "stepId", i, "ctxid", mpcCtx.ContextID)
			log.Info("\n")
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

func (mpcCtx *MpcContext) SchnorrMPCer() mpcprotocol.SchnorrMPCer {
	return mpcCtx.schnorrMPCer
}

func (mpcCtx *MpcContext) SetSchnorrMPCer(smcer mpcprotocol.SchnorrMPCer) {
	mpcCtx.schnorrMPCer = smcer
}

func (mpcCtx *MpcContext) SetStepSchnorrMPCer() {
	for _, step := range mpcCtx.MpcSteps {
		step.SetSchnorrMpcer(mpcCtx.schnorrMPCer)
	}
}
