package step

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcRRcvJudgeStep struct {
	BaseStep
	rcvColInterMap map[*discover.NodeID]*big.Int
	rcvColInter    *big.Int
}

func CreateMpcRRcvJudgeStep(peers *[]mpcprotocol.PeerInfo) *MpcRRcvJudgeStep {
	log.SyslogInfo("CreateMpcRRcvJudgeStep begin")

	mpc := &MpcRRcvJudgeStep{
		*CreateBaseStep(peers, -1),
		make(map[*discover.NodeID]*big.Int, 0),
		nil}
	return mpc
}

func (ptStep *MpcRRcvJudgeStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("MpcRRcvJudgeStep.InitStep begin")
	ptStep.BaseStep.InitStep(result)

	ret, err := result.GetValue(mpcprotocol.RRcvedCollInter)
	if err != nil {
		log.SyslogErr("MpcRRcvJudgeStep", "InitStep.getValue error", err.Error())
		return err
	}
	if len(ret) == 0 {
		log.SyslogErr("MpcRRcvJudgeStep", "GetValue len(ret)", len(ret))
		return err
	}
	ptStep.rcvColInter = &ret[0]
	log.SyslogInfo("......MpcRRcvJudgeStep.InitStep end", "RRcvedCollInter", hexutil.Encode(ptStep.rcvColInter.Bytes()))
	log.SyslogInfo("MpcRRcvJudgeStep.InitStep end")
	return nil
}

func (ptStep *MpcRRcvJudgeStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("MpcRRcvJudgeStep.CreateMessage begin")
	message := make([]mpcprotocol.StepMessage, 1)
	message[0].MsgCode = mpcprotocol.MPCMessage
	message[0].PeerID = nil

	var buf bytes.Buffer
	buf.Write(ptStep.rcvColInter.Bytes())
	h := sha256.Sum256(buf.Bytes())

	prv, _ := osmconf.GetOsmConf().GetSelfPrvKey()
	r, s, _ := schcomm.SignInternalData(prv, h[:])

	message[0].Data = make([]big.Int, 3)
	message[0].Data[0] = *ptStep.rcvColInter
	message[0].Data[1] = *r
	message[0].Data[2] = *s
	log.SyslogInfo("MpcRRcvJudgeStep.CreateMessage end")
	return message
}

func (ptStep *MpcRRcvJudgeStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	log.SyslogInfo("MpcRRcvJudgeStep.HandleMessage begin")
	r := msg.Data[1]
	s := msg.Data[2]

	var buf bytes.Buffer
	buf.Write(msg.Data[0].Bytes())
	h := sha256.Sum256(buf.Bytes())

	_, grpIdStr, err := osmconf.GetGrpId(ptStep.mpcResult)
	if err != nil {
		log.SyslogErr("MpcRRcvInterStep", "HandleMessage error", err.Error())
	}

	senderPk, err := osmconf.GetOsmConf().GetPKByNodeId(grpIdStr, msg.PeerID)
	if err != nil {
		log.SyslogErr("MpcRRcvInterStep", "GetPKByNodeId error", err.Error())
	}

	bVerifySig := schcomm.VerifyInternalData(senderPk, h[:], &r, &s)

	if bVerifySig {
		log.SyslogInfo("MpcRRcvInterStep::HandleMessage check sig success")
		ptStep.rcvColInterMap[msg.PeerID] = &msg.Data[0]
	} else {
		log.SyslogErr("......MpcRRcvInterStep::HandleMessage check sig fail")
	}

	log.SyslogInfo("........................Intersection collection information",
		" self Intersection collection", hexutil.Encode(ptStep.rcvColInter.Bytes()),
		"peerID", msg.PeerID.String(),
		"peers intersection collection", hexutil.Encode(msg.Data[0].Bytes()))

	log.SyslogInfo("MpcRRcvJudgeStep.HandleMessage end")

	return true
}

func (ptStep *MpcRRcvJudgeStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	log.SyslogInfo("MpcRRcvJudgeStep.FinishStep begin")

	// compute the intersec and save
	err := ptStep.BaseStep.FinishStep()
	if err != nil {
		return err
	}

	_, grpIdString, err := osmconf.GetGrpId(result)
	if err != nil {
		log.SyslogErr("MpcRRcvJudgeStep", "error in GetGrpId", err.Error())
		return err
	}

	leaderIndex, _ := osmconf.GetOsmConf().GetLeaderIndex(grpIdString)
	bIncludeLeader, err := osmconf.IsHaming(ptStep.rcvColInter, leaderIndex)
	if err != nil {
		log.SyslogErr("MpcRRcvJudgeStep", "error in IsHaming", err.Error())
		return err
	}
	// 1. should include leaderIndex
	if !bIncludeLeader {
		log.SyslogErr("MpcRRcvJudgeStep leader is not included in the intersection")
		return err
	} else {
		log.SyslogInfo("......self  rcvColInter include leader index")
	}

	// 2. others' inter collection should be equal to self's inter collection
	for _, rcvCol := range ptStep.rcvColInterMap {
		if ptStep.rcvColInter.Cmp(rcvCol) != 0 {
			log.SyslogErr("........................MpcRRcvJudgeStep received colInter not equal to self's",
				"received", hexutil.Encode(rcvCol.Bytes()),
				"self", hexutil.Encode(ptStep.rcvColInter.Bytes()))

			return errors.New(fmt.Sprintf("Inersection collection is not consistent"))
		}
	}

	// 3. RRcvedColl == RRcvedCollInter
	rrcvedCol, err := result.GetValue(mpcprotocol.RRcvedColl)
	if err != nil {
		log.SyslogErr("MpcRRcvJudgeStep", "GetValue RRcvedcoll error", err.Error())
		return err
	}
	if rrcvedCol[0].Cmp(ptStep.rcvColInter) == 0 {
		log.SyslogInfo("......rrcvedCol is equal rcvColInter")
		return nil
	}
	// 4. RRcvedColl != RRcvedCollInter
	// 5. build rskShare and rpkShare
	log.SyslogInfo("......rrcvedCol is NOT equal rcvColInter")

	totalNumber, err := osmconf.GetOsmConf().GetTotalNum(grpIdString)
	if err != nil {
		log.SyslogErr("MpcRRcvJudgeStep.FinishStep", "getTotalNumber err", err.Error())
		return err
	}

	bigs := make([]big.Int, 0)
	for i := 0; i < int(totalNumber); i++ {
		b, err := osmconf.IsHaming(ptStep.rcvColInter, uint16(i))
		if err != nil {
			log.SyslogErr("MpcRRcvJudgeStep.FinishStep", "IsHaming err", err.Error())
			return err
		}
		if b {
			key := mpcprotocol.RSKSIJ + strconv.Itoa(int(i))
			sij, err := result.GetValue(key)
			if err != nil {
				log.SyslogErr("MpcRRcvJudgeStep.FinishStep", "get sij err", err.Error())
				return err
			}
			bigs = append(bigs, sij[i])
		}
	}

	// get rskShare
	rskShare := big.NewInt(0)
	for _, value := range bigs {
		rskShare.Add(rskShare, &value)
		rskShare.Mod(rskShare, crypto.S256().Params().N)
	}

	err = result.SetValue(mpcprotocol.RSkShare, []big.Int{*rskShare})
	if err != nil {
		return err
	}

	log.SyslogInfo("......MpcRRcvJudgeStep.FinishStep setValue",
		"key", mpcprotocol.RSkShare,
		"value", hexutil.Encode(rskShare.Bytes()))

	rpkShare := new(ecdsa.PublicKey)
	rpkShare.Curve = crypto.S256()
	rpkShare.X, rpkShare.Y = crypto.S256().ScalarBaseMult(rskShare.Bytes())

	selfIndex, err := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	if err != nil {
		log.SyslogErr("MpcRRcvJudgeStep.FinishStep", "FinishStep", err.Error())
		return err
	}
	key := mpcprotocol.RPkShare + strconv.Itoa(int(selfIndex))
	err = result.SetByteValue(key, crypto.FromECDSAPub(rpkShare))
	if err != nil {
		return err
	}

	log.SyslogInfo("......MpcRRcvJudgeStep.FinishStep SetByteValue",
		"key", key,
		"value", hexutil.Encode(crypto.FromECDSAPub(rpkShare)))

	log.SyslogInfo("MpcRRcvJudgeStep.FinishStep end")
	return nil
}
