package step

import (
	"bytes"
	"crypto/rand"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

const (
	MpcPolycmStepMsgDataNumber = 2
)
type MpcPolycmStep struct {
	BaseStep
	message     map[discover.NodeID]bool
	polycmGMap  	schnorrmpc.PolyGMap
	polycmGMSigMap	schnorrmpc.PolyGSigMap
	polyCoff	schnorrmpc.Polynomial
	selfIndex	uint16
	grpId		string
}

func CreateMpcPolycmStep(peers *[]mpcprotocol.PeerInfo) *MpcPolycmStep {

	return &MpcPolycmStep{
		BaseStep:    *CreateBaseStep(peers, len(*peers)-1),
		message:     make(map[discover.NodeID]bool),
		polycmGMap:  make(schnorrmpc.PolyGMap),
		polycmGMSigMap:  make(schnorrmpc.PolyGSigMap),
		polyCoff:	 make(schnorrmpc.Polynomial,1)}
}

func (req *MpcPolycmStep) InitStep(result mpcprotocol.MpcResultInterface) error {
	log.SyslogInfo("MpcPolycm Step.InitStep begin")
	req.BaseStep.InitStep(result)
	// build self polynomial
	threshold, _ := osmconf.GetOsmConf().GetThresholdNum()
	degree := threshold -1
	s, err := rand.Int(rand.Reader, crypto.S256().Params().N)
	if err != nil {
		log.SyslogErr("MpcPolycmStep::InitStep", "rand.Int fail. err", err.Error())
		return err
	}

	cof := schnorrmpc.RandPoly(int(degree), *s)
	copy(req.polyCoff, cof)

	// build polycmG
	pg := make(schnorrmpc.PolynomialG,threshold)
	for index, value := range cof {
		skG, _ := schnorrmpc.SkG(&value)
		pg[index] = *skG
	}
	// todo error
	grpId,_ := result.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)
	req.grpId = grpIdString
	selfIndex, _ := osmconf.GetOsmConf().GetSelfInx(grpIdString)
	req.selfIndex = selfIndex
	req.polycmGMap[selfIndex] = pg
	return nil
}

func (req *MpcPolycmStep) CreateMessage() []mpcprotocol.StepMessage {
	// broad case self polynomialG
	// grpId + threshold G + R + S
	log.SyslogInfo("MpcPolycmStep.CreateMessage.....")
	log.Info("MpcPolycmStep","CreateMessage peers",*req.peers)
	msg := mpcprotocol.StepMessage{
		MsgCode:   mpcprotocol.MPCMessage,
		PeerID:    nil,
		Peers:     req.peers,
		Data:      nil,
		BytesData: nil}
	threshold, _ := osmconf.GetOsmConf().GetThresholdNum()
	// Data[0]: R
	// Data[1]: S
	msg.Data = make([]big.Int, 2)
	// BytesData[i]: the ith poly commit G
	msg.BytesData = make([][]byte,threshold)
	// build msg.data & msg.bytedata
	var buf bytes.Buffer
	for index, cmItem := range req.polycmGMap[req.selfIndex] {
		buf.Write(crypto.FromECDSAPub(&cmItem))
		msg.BytesData[index] = crypto.FromECDSAPub(&cmItem)
	}

	//prv,_ := osmconf.GetOsmConf().GetSelfPrvKey()
	//h := sha256.Sum256(buf.Bytes())
	r,s,_ := schnorrmpc.SignInternalData(buf.Bytes())
	msg.Data[0] = *r
	msg.Data[1] = *s

	return []mpcprotocol.StepMessage{msg}
}

func (req *MpcPolycmStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	err := req.BaseStep.FinishStep()
	if err != nil {
		return err
	}
	// save other poly commit to the mpc context
	for index, polyCms := range req.polycmGMap {
		key := mpcprotocol.MPCRPolyCMG + strconv.Itoa(int(index))
		var buf bytes.Buffer
		for _, polyCmItem := range polyCms{
			buf.Write(crypto.FromECDSAPub(&polyCmItem))
		}
		result.SetByteValue(key, buf.Bytes())
	}

	// save other poly commit to the mpc context
	for index, polyCmsSig := range req.polycmGMSigMap {
		key := mpcprotocol.MPCRPolyCMG + strconv.Itoa(int(index))

		bigs := make([]big.Int,2)
		bigs[0] = polyCmsSig[0]
		bigs[1] = polyCmsSig[1]
		result.SetValue(key, bigs)
	}

	// save self poly commit coff to the mpc context
	key := mpcprotocol.MPCRPolyCoff + strconv.Itoa(int(req.selfIndex))

	coff := make([]big.Int, 0)
	for _, polyCmCoffItem := range req.polyCoff{
		coff = append(coff, polyCmCoffItem)
	}
	result.SetValue(key, coff[:])
	return nil
}

func (req *MpcPolycmStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	// save others polynomial
	log.SyslogInfo("MpcPolycmStep::HandleMessage","MpcPolycmStep.HandleMessage begin, peerID", msg.PeerID.String())
	_, exist := req.message[*msg.PeerID]
	if exist {
		log.SyslogErr("MpcPolycmStep::HandleMessage","MpcPolycmStep.HandleMessage, get message from peerID fail. peer",
			msg.PeerID.String())
		return false
	}

	req.message[*msg.PeerID] = true

	threshold, _ := osmconf.GetOsmConf().GetThresholdNum()
	if len(msg.BytesData) != int(threshold) {
		// todo data has error
		return false
	}
	if len(msg.Data) != MpcPolycmStepMsgDataNumber {
		// todo
		return false
	}
	if !req.checkSig(msg) {
		return false
	}
	req.fillCmIntoMap(msg)
	return true
}


func (req *MpcPolycmStep) checkSig(msg *mpcprotocol.StepMessage) bool {
	// todo check the sig of polyCommit
	return true
}

func (req *MpcPolycmStep) fillCmIntoMap(msg *mpcprotocol.StepMessage) bool {
	nodeId := msg.PeerID
	inx, _ := osmconf.GetOsmConf().GetInxByNodeId(req.grpId,nodeId)


	threshold, _ := osmconf.GetOsmConf().GetThresholdNum()
	// build polycmG
	pg := make(schnorrmpc.PolynomialG,threshold)

	for i := 0; i< len(msg.BytesData);i++ {
		pk := crypto.ToECDSAPub(msg.BytesData[i])
		pg[i] = *pk
	}
	req.polycmGMap[inx] = pg

	req.polycmGMSigMap[inx][0] = msg.Data[0]
	req.polycmGMSigMap[inx][1] = msg.Data[1]

	return true
}
