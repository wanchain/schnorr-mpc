package step

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

type MpcSStep struct {
	BaseMpcStep
	resultKeys []string
	signNum    int
	SShareErrNum	int

	sshareOKIndex  []uint16
	sshareKOIndex  []uint16
	sshareNOIndex  []uint16
}

func CreateMpcSStep(peers *[]mpcprotocol.PeerInfo, preValueKeys []string, resultKeys []string) *MpcSStep {

	log.SyslogInfo("CreateMpcSStep begin")
	signNum := len(preValueKeys)
	mpc := &MpcSStep{*CreateBaseMpcStep(peers, signNum), resultKeys, signNum,0,
	make([]uint16,0),make([]uint16,0),make([]uint16,0)}

	//	MpcPrivateShare
	//  MpcS
	for i := 0; i < signNum; i++ {
		mpc.messages[i] = createSGenerator(preValueKeys[i])
	}

	return mpc
}

func (msStep *MpcSStep) CreateMessage() []mpcprotocol.StepMessage {
	log.SyslogInfo("MpcSStep.CreateMessage begin")
	// sshare, sig of sshare
	// only send to leader??

	message := make([]mpcprotocol.StepMessage, 1)
	message[0].MsgCode = mpcprotocol.MPCMessage
	message[0].PeerID = nil
	//message[0].PeerID = leaderNodeId

	for i := 0; i < msStep.signNum; i++ {
		pointer := msStep.messages[i].(*mpcSGenerator)

		h := sha256.Sum256(pointer.seed.Bytes())
		prv,_ := osmconf.GetOsmConf().GetSelfPrvKey()
		r,s,_ := schnorrmpc.SignInternalData(prv,h[:])

		message[0].Data = append(message[0].Data, pointer.seed)
		message[0].Data = append(message[0].Data, *r)
		message[0].Data = append(message[0].Data, *s)
	}

	return message
}

func (msStep *MpcSStep) HandleMessage(msg *mpcprotocol.StepMessage) bool {
	// todo check sig of s, check s data
	// todo if error, save error info
	// todo send error to leader for judging
	log.SyslogInfo("MpcSStep::HandleMessage","MpcSStep.HandleMessage begin, peerID", msg.PeerID.String())


	for i := 0; i < msStep.signNum; i++ {
		pointer := msStep.messages[i].(*mpcSGenerator)
		_, exist := pointer.message[*msg.PeerID]
		if exist {
			log.SyslogErr("MpcSStep::HandleMessage","MpcSStep.HandleMessage, get msg from seed fail. peer", msg.PeerID.String())
			return false
		}

		sshare := msg.Data[3*i]
		r := msg.Data[3*i+1]
		s := msg.Data[3*i+2]

		grpId,_ := msStep.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
		grpIdString := string(grpId)
		senderPk,_ := osmconf.GetOsmConf().GetPKByNodeId(grpIdString,msg.PeerID)
		senderIndex,_ := osmconf.GetOsmConf().GetInxByNodeId(grpIdString,msg.PeerID)

		// 1. check sig
		h:=sha256.Sum256(sshare.Bytes())
		bVerifySig := schnorrmpc.VerifyInternalData(senderPk,h[:],&r,&s)

		if !bVerifySig {
			// save error and send judge info to leader
			log.SyslogErr("MpcPointStep::HandleMessage"," check sig fail")
			// save error for check data of s
			key := mpcprotocol.RPkShare + strconv.Itoa(int(senderIndex))
			msStep.mpcResult.SetByteValue(key,msg.BytesData[i])

		}else{
			log.SyslogInfo("check sig of sshare successfully","senderIndex",senderIndex)
		}

		// 2. check content
		selfIndex, _ := osmconf.GetOsmConf().GetSelfInx(grpIdString)

		log.SyslogInfo("===================================MpcSStep","senderIndex",senderIndex,"selfIndex",selfIndex)

		rpkShare,_ := msStep.getRPkShare(senderIndex)
		gpkShare,_ := msStep.getGPKShare(senderIndex)
		m,_:= msStep.getm()
		bContentCheck,_ := msStep.checkContent(&sshare,m,rpkShare,gpkShare)

		if bContentCheck {
			log.SyslogInfo("check content of sshare successfully","senderIndex",senderIndex)
		}

		// 3. write error sshare
		// 3.1 write error count
		// 3.2 write error info
		if !bContentCheck || !bVerifySig {
			msStep.SShareErrNum += 1

			msStep.sshareKOIndex = append(msStep.sshareKOIndex,senderIndex)

			sshareErrInfo := make([]big.Int,5)
			// sendIndex, rvcIndex, sshare, r, s
			sshareErrInfo[0] = *big.NewInt(0).SetInt64(int64(senderIndex))
			sshareErrInfo[1] = *big.NewInt(0).SetInt64(int64(selfIndex))
			sshareErrInfo[2] = sshare
			sshareErrInfo[3] =	r
			sshareErrInfo[4] =	s

			// save error info
			keyErrInfo := mpcprotocol.SShareErrInfos + strconv.Itoa(int(msStep.SShareErrNum) -1)
			msStep.mpcResult.SetValue(keyErrInfo,sshareErrInfo)

		}else{
			log.SyslogInfo("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@check sshare successfully","senderIndex",senderIndex)
			msStep.sshareOKIndex = append(msStep.sshareOKIndex,senderIndex)

			pointer.message[*msg.PeerID] = sshare
		}

		// save error number errNum=0:no error.
		keyErrNum := mpcprotocol.SShareErrNum
		rskErrInfoNum := make([]big.Int,1)
		rskErrInfoNum[0] = *big.NewInt(0).SetInt64(int64(msStep.SShareErrNum))
		msStep.mpcResult.SetValue(keyErrNum,rskErrInfoNum)
	}

	return true
}

func (msStep *MpcSStep) FinishStep(result mpcprotocol.MpcResultInterface, mpc mpcprotocol.StoremanManager) error {
	log.SyslogInfo("MpcSStep.FinishStep begin")

	// save index for incentive and slash

	grpId,_ := msStep.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)
	allIndex,_ := osmconf.GetOsmConf().GetGrpElemsInxes(grpIdString)
	tempIndex := osmconf.Difference(*allIndex,msStep.sshareOKIndex)
	msStep.sshareNOIndex = osmconf.Difference(tempIndex,msStep.sshareKOIndex)

	okIndex := make([]big.Int,len(msStep.sshareOKIndex))
	koIndex := make([]big.Int,len(msStep.sshareKOIndex))
	noIndex := make([]big.Int,len(msStep.sshareNOIndex))

	for i,value := range msStep.sshareOKIndex{
		okIndex[i].SetInt64(int64(value))
	}

	for i,value := range msStep.sshareKOIndex{
		koIndex[i].SetInt64(int64(value))
	}

	for i,value := range msStep.sshareNOIndex{
		noIndex[i].SetInt64(int64(value))
	}

	msStep.mpcResult.SetValue(mpcprotocol.SOKIndex,okIndex)
	msStep.mpcResult.SetValue(mpcprotocol.SKOIndex,koIndex)
	msStep.mpcResult.SetValue(mpcprotocol.SNOIndex,noIndex)


	err := msStep.BaseMpcStep.FinishStep()
	if err != nil {
		_,retHash := msStep.BaseMpcStep.GetSignedDataHash(result)
		msStep.BaseMpcStep.ShowNotArriveNodes(retHash,mpc.SelfNodeId())

		return err
	}

	for i := 0; i < msStep.signNum; i++ {
		pointer := msStep.messages[i].(*mpcSGenerator)
		// MpcS

		log.SyslogInfo("%%%%%%%%%%%%%%%%%%%%MPCSStep","s", hexutil.Encode(pointer.result.Bytes()))

		err = result.SetValue(msStep.resultKeys[i], []big.Int{pointer.result})
		if err != nil {
			log.SyslogErr("MpcSStep::FinishStep","MpcSStep.FinishStep, SetValue fail. err", err.Error())
			return err
		}
	}

	log.SyslogInfo("MpcSStep.FinishStep succeed")
	return nil
}



func (msStep *MpcSStep) checkContent(sshare, m *big.Int, rpkShare,gpkShare *ecdsa.PublicKey) (bool,error) {
	// todo check input parameters
	sshareG,_ := schnorrmpc.SkG(sshare)
	mPkShare, _ := schnorrmpc.SkMul(gpkShare,m)

	pkTemp := new(ecdsa.PublicKey)
	pkTemp.Curve = crypto.S256()
	pkTemp.X, pkTemp.Y = rpkShare.X, rpkShare.Y
	pkTemp.X, pkTemp.Y = crypto.S256().Add(pkTemp.X,pkTemp.Y,mPkShare.X,mPkShare.Y)

	left := sshareG
	right := pkTemp
	return schnorrmpc.PkEqual(left,right)
}

func (msStep *MpcSStep) getRPkShare(index uint16) (*ecdsa.PublicKey,error) {

	key := mpcprotocol.RPkShare + strconv.Itoa(int(index))

	log.SyslogInfo("getRPkShare","index",index,"key",key)
	pkBytes,err := msStep.mpcResult.GetByteValue(key)
	if err != nil {
		log.SyslogErr("getRPkShare","err",err.Error())
	}

	return crypto.ToECDSAPub(pkBytes),nil
}

func (msStep *MpcSStep) getm() (*big.Int,error) {
	// check signVerify
	result := msStep.mpcResult
	M, err := result.GetByteValue(mpcprotocol.MpcM)
	if err != nil {
		log.SyslogErr("MpcAckRSStep::verifyRS","ack MpcAckRSStep get MpcM . err", err.Error())
		return &big.Int{}, err
	}

	hashMBytes := sha256.Sum256(M)

	// rpk : R
	rpkBytes,_ := result.GetByteValue(mpcprotocol.RPk)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	//buffer.Write(M[:])
	buffer.Write(hashMBytes[:])
	buffer.Write(rpkBytes)
	mTemp := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(mTemp[:])

	return m,nil
}

func (msStep *MpcSStep) getGPKShare(index uint16) (*ecdsa.PublicKey,error) {
	//
	grpId,_ := msStep.mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	grpIdString := string(grpId)

	gpkShare, _ := osmconf.GetOsmConf().GetPKShare(grpIdString,index)

	return gpkShare,nil
}