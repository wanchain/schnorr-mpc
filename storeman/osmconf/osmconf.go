package osmconf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wanchain/schnorr-mpc/accounts"
	"github.com/wanchain/schnorr-mpc/accounts/keystore"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"io/ioutil"
	"math/big"
	"path"
	"strconv"
	"strings"
	"sync"
)

const EmptyString = ""

var osmConf *OsmConf

type GrpElem struct {
	Inx       uint16
	WorkingPk *ecdsa.PublicKey
	NodeId    *discover.NodeID
	PkShare   *ecdsa.PublicKey
	XValue    *big.Int
}

type ArrayGrpElem []GrpElem

type ArrayGrpElemsInx []uint16

type GrpInfoItem struct {
	GrpId        string
	GrpGpkBytes  hexutil.Bytes
	LeaderInx    uint16
	TotalNum     uint16
	ThresholdNum uint16
	ArrGrpElems  ArrayGrpElem
}

type OsmConf struct {
	GrpInfoMap      map[string]GrpInfoItem
	SelfNodeId      *discover.NodeID
	GpkPassword     string
	WorkingPassword string
	AccMng          *accounts.Manager
	confPath        string
	pwdPath         string
	wrLock          sync.RWMutex
	pwdFileMap      map[string]string
}

//-----------------------configure content begin ---------------------------------
type GrpElemContent struct {
	Inx       string        `json:"index"`
	WorkingPk hexutil.Bytes `json:"workingPk"`
	NodeId    hexutil.Bytes `json:"nodeId"`
	PkShare   hexutil.Bytes `json:"pkShare"`
}

type GrpInfoItemContent struct {
	GrpId           string           `json:"grpId"`
	GrpPk           hexutil.Bytes    `json:"grpPk"`
	LeaderInx       string           `json:"leaderInx"`
	TotalNumber     string           `json:"totalNumber"`
	ThresholdNumber string           `json:"thresholdNumber"`
	GrpElms         []GrpElemContent `json:"grpElms"`
}

type OsmFileContent struct {
	GrpInfo []GrpInfoItemContent
}

//-----------------------configure content end ---------------------------------

func GetOsmConf() *OsmConf {

	if osmConf == nil {
		osmConf = new(OsmConf)
		return osmConf
	}
	return osmConf

}

//-----------------------mange config file ---------------------------------

func (cnf *OsmConf) LoadCnf(confPath string) error {

	defer cnf.wrLock.Unlock()

	if confPath == EmptyString {
		panic("confPath is empty")
	}
	ofcContent := OsmFileContent{}

	filePath := confPath

	cnf.wrLock.Lock()

	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.SyslogErr("LoadCnf.ReadFile", "error", err.Error())
		panic(err.Error())
	}
	errUnmarshal := json.Unmarshal(b, &ofcContent)
	if errUnmarshal != nil {
		log.SyslogErr("LoadCnf.Unmarshal", "error", err.Error())
		panic(errUnmarshal)
	}

	// save configure file content to the OsmConf struct.

	cnf.GrpInfoMap = make(map[string]GrpInfoItem, len(ofcContent.GrpInfo))
	for _, grpInfo := range ofcContent.GrpInfo {
		gii := GrpInfoItem{}

		gii.GrpId = grpInfo.GrpId

		gii.GrpGpkBytes = grpInfo.GrpPk

		leaderIndex, _ := strconv.Atoi(grpInfo.LeaderInx)
		gii.LeaderInx = uint16(leaderIndex)

		TotalNum, _ := strconv.Atoi(grpInfo.TotalNumber)
		gii.TotalNum = uint16(TotalNum)

		ThresholdNum, _ := strconv.Atoi(grpInfo.ThresholdNumber)
		gii.ThresholdNum = uint16(ThresholdNum)

		gii.ArrGrpElems = make(ArrayGrpElem, len(grpInfo.GrpElms))

		for i, ge := range grpInfo.GrpElms {

			Inx, _ := strconv.Atoi(ge.Inx)
			gii.ArrGrpElems[i].Inx = uint16(Inx)
			gii.ArrGrpElems[i].PkShare = crypto.ToECDSAPub(ge.PkShare)
			log.SyslogInfo("LoadCnf", "ge.WorkingPk", ge.WorkingPk)
			log.SyslogInfo("LoadCnf", "ge.PkShare", ge.PkShare)

			gii.ArrGrpElems[i].WorkingPk = crypto.ToECDSAPub(ge.WorkingPk)

			nodeId := discover.NodeID{}
			copy(nodeId[:], ge.NodeId[:])
			gii.ArrGrpElems[i].NodeId = &nodeId

			h := sha256.Sum256(ge.WorkingPk)
			gii.ArrGrpElems[i].XValue = big.NewInt(0).SetBytes(h[:])
		}

		cnf.GrpInfoMap[grpInfo.GrpId] = gii
	}
	return nil
}

func (cnf *OsmConf) FreshCnf(confPath string) error {
	if confPath == EmptyString {
		panic("confPath is empty")
	}
	return cnf.LoadCnf(confPath)
}

func (cnf *OsmConf) checkGrpId(grpId string) bool {
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	if _, ok := cnf.GrpInfoMap[grpId]; !ok {
		panic(fmt.Sprintf("checkGrpId: groupId does not exist in storeman group. grpId %v", grpId))
	} else {
		return true
	}
}

func (cnf *OsmConf) GetThresholdNum(grpId string) (uint16, error) {
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)

	return cnf.GrpInfoMap[grpId].ThresholdNum, nil

}

func (cnf *OsmConf) GetTotalNum(grpId string) (uint16, error) {
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)

	return cnf.GrpInfoMap[grpId].TotalNum, nil
}

//-----------------------get pk ---------------------------------

// get working pk
func (cnf *OsmConf) GetPK(grpId string, smInx uint16) (*ecdsa.PublicKey, error) {
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem {
		if value.Inx == smInx {
			return value.WorkingPk, nil
		}
	}
	panic(fmt.Sprintf("GetPK:Not find storeman, smInx %v", smInx))
}

func (cnf *OsmConf) GetPKByNodeId(grpId string, nodeId *discover.NodeID) (*ecdsa.PublicKey, error) {
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	if nodeId == nil {
		log.SyslogErr("GetPKByNodeId, nodeId is null")
		panic("GetPKByNodeId, nodeId is null")
	}
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem {
		if *value.NodeId == *nodeId {
			return value.WorkingPk, nil
		}
	}
	panic(fmt.Sprintf("GetPKByNodeId:Not find storeman, nodeId %v", *nodeId))

}

// get gpk share (public share)
func (cnf *OsmConf) GetPKShare(grpId string, smInx uint16) (*ecdsa.PublicKey, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem {
		if value.Inx == smInx {
			return value.PkShare, nil
		}
	}

	panic(fmt.Sprintf("GetPKShare:Not find storeman, smInx %v", smInx))
}

func (cnf *OsmConf) GetPKShareByNodeId(grpId string, nodeId *discover.NodeID) (*ecdsa.PublicKey, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	if nodeId == nil {
		log.SyslogErr("GetPKShareByNodeId, nodeId is null")
		panic("GetPKShareByNodeId, nodeId is null")
	}
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem {
		if *value.NodeId == *nodeId {
			return value.PkShare, nil
		}
	}
	panic(fmt.Sprintf("GetPKShareByNodeId:Not find storeman, nodeId %v", *nodeId))
}

//-----------------------get self---------------------------------

func (cnf *OsmConf) GetSelfPubKey() (*ecdsa.PublicKey, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	for _, grpInfo := range cnf.GrpInfoMap {
		for _, grpElem := range grpInfo.ArrGrpElems {
			if *grpElem.NodeId == *cnf.SelfNodeId {
				return grpElem.WorkingPk, nil
			}
		}
	}
	panic(fmt.Sprintf("GetSelfPubKey:Not find storeman, selfNodeId %v", *cnf.SelfNodeId))
}

func (cnf *OsmConf) GetSelfInx(grpId string) (uint16, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	return cnf.GetInxByNodeId(grpId, cnf.SelfNodeId)
}

func (cnf *OsmConf) GetSelfNodeId() (*discover.NodeID, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	return cnf.SelfNodeId, nil
}

func (cnf *OsmConf) GetSelfPrvKey() (*ecdsa.PrivateKey, error) {
	pk, err := cnf.GetSelfPubKey()
	if err != nil {
		log.SyslogErr("OsmConf", "GetSelfPrvKey.GetSelfPubKey", err.Error())
		return nil, err
	}
	err = schnorrmpc.CheckPK(pk)
	if err != nil {
		log.SyslogErr("OsmConf", "GetSelfPrvKey.CheckPK", err.Error())
		return nil, err
	}
	address, err := pkToAddr(crypto.FromECDSAPub(pk))
	log.SyslogInfo("GetSelfPrvKey", "pk", hexutil.Encode(crypto.FromECDSAPub(pk)), "address", address.String())
	if err != nil {
		panic("Error in pk to address")
		return nil, err
	}

	ks := cnf.AccMng.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	account := accounts.Account{Address: address}
	account, err = ks.Find(account)
	if err != nil {
		//find account from keystore fail
		panic("find account from keystore fail")
		return nil, err
	}

	var keyjson []byte
	log.Info("GetSelfPrvKey", "account.URL.Path", account.URL.Path)
	keyjson, err = ioutil.ReadFile(account.URL.Path)

	if err != nil {
		// get account keyjson fail
		panic("find account from keystore fail")
		return nil, err
	}

	wkPassword, _ := cnf.GetWkPwd(address.String())
	//key, err := keystore.DecryptKey(keyjson, cnf.WorkingPassword)
	key, err := keystore.DecryptKey(keyjson, wkPassword)
	if err != nil {
		// decrypt account keyjson fail
		log.Info("GetSelfPrvKey", "DecryptKey err ", err)
		panic("DecryptKey account from keystore fail")
		return nil, err
	}
	return key.PrivateKey, nil
}

func (cnf *OsmConf) SetSelfNodeId(id *discover.NodeID) error {
	defer cnf.wrLock.Unlock()
	cnf.wrLock.Lock()

	if id == nil {
		log.SyslogErr("GetPKShareByNodeId, nodeId is null")
		panic("SetSelfNodeId, nodeId is null")
	}
	log.SyslogInfo(fmt.Sprintf(">>>>>>>SetSelfNodeId %v \n", id.String()))
	cnf.SelfNodeId = id

	return nil
}

//func (cnf *OsmConf) SetGpkPassword(pwd string) error {
//	cnf.GpkPassword = pwd
//	return nil
//}
//
//func (cnf *OsmConf) SetWkPassword(pwd string) error {
//	cnf.WorkingPassword = pwd
//	return nil
//}

func (cnf *OsmConf) SetAccountManger(accMng *accounts.Manager) error {

	if accMng == nil {
		panic(fmt.Sprintf("SetAccountManger accMng is null"))
	}
	cnf.AccMng = accMng
	return nil
}

func (cnf *OsmConf) SetFilePath(path string) error {
	if path == EmptyString {
		panic(fmt.Sprintf("SetFilePath path is empty"))
	}
	cnf.confPath = path
	return nil
}

func (cnf *OsmConf) GetGpkPwd(gpk string) (string, error) {

	fn, _ := cnf.getPwdFileName(gpk + ".pwd")
	fileName := path.Join(cnf.pwdPath, fn)
	// get password from file
	return cnf.GetPwd(fileName)
}

func (cnf *OsmConf) GetWkPwd(address string) (string, error) {
	fn, _ := cnf.getPwdFileName(address + ".pwd")
	fileName := path.Join(cnf.pwdPath, fn)
	return cnf.GetPwd(fileName)
}

func (cnf *OsmConf) GetPwd(fileName string) (string, error) {
	if fileName == "" {
		panic(fmt.Sprintf("password file [:%v] is not existing", fileName))
	}
	text, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(fmt.Sprintf("Failed to read password file:[%v]", fileName))
	}
	lines := strings.Split(string(text), "\n")
	if len(lines) == 0 {
		panic(fmt.Sprintf("empty password [%v]", fileName))
	}
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines[0], nil
}

func (cnf *OsmConf) SetPwdPath(path string) error {
	if path == EmptyString {
		panic(fmt.Sprintf("SetFilePath path is empty"))
	}
	cnf.pwdPath = path
	cnf.buildPwdMap(path)
	return nil
}

func (cnf *OsmConf) buildPwdMap(dir string) error {
	cnf.pwdFileMap = make(map[string]string, 0)
	flist, err := ioutil.ReadDir(dir)

	if err != nil {
		return err
	}

	for _, f := range flist {
		key := strings.ToUpper(f.Name())
		cnf.pwdFileMap[key] = f.Name()
	}
	return nil
}

func (cnf *OsmConf) getPwdFileName(incaseFielName string) (string, error) {
	ret, ok := cnf.pwdFileMap[strings.ToUpper(incaseFielName)]
	if ok {
		return ret, nil
	}
	return incaseFielName, nil
}

//-----------------------get group---------------------------------

func (cnf *OsmConf) GetGrpElemsInxes(grpId string) (*ArrayGrpElemsInx, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	cnf.checkGrpId(grpId)
	ret := make(ArrayGrpElemsInx, len(cnf.GrpInfoMap[grpId].ArrGrpElems))
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for index, value := range arrGrpElem {
		ret[index] = value.Inx
	}
	return &ret, nil
}

func (cnf *OsmConf) GetGrpElems(grpId string) (*ArrayGrpElem, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	cnf.checkGrpId(grpId)
	ArrayGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	return &ArrayGrpElem, nil

}

func (cnf *OsmConf) GetGrpItem(grpId string, smInx uint16) (*GrpElem, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	cnf.checkGrpId(grpId)
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems

	for index, grpElem := range arrGrpElem {
		if uint16(index) == smInx {
			return &grpElem, nil
		}
	}
	panic(fmt.Sprintf("GetGrpItem error. grpId = %v,smInx=%v", grpId, smInx))
}

func (cnf *OsmConf) GetGrpInxByGpk(gpk hexutil.Bytes) (string, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	for index, value := range cnf.GrpInfoMap {

		if bytes.Compare(value.GrpGpkBytes, gpk) == 0 {
			return index, nil
		}

	}
	panic(fmt.Sprintf("GetGrpInxByGpk error. gpk = %v ", hexutil.Encode(gpk)))
}

//-----------------------others ---------------------------------

// compute f(x) x=hash(pk)
func (cnf *OsmConf) getPkHash(grpId string, smInx uint16) (common.Hash, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	pk, _ := cnf.GetPK(grpId, smInx)
	err := schnorrmpc.CheckPK(pk)
	if err != nil {
		return common.Hash{}, err
	}
	h := sha256.Sum256(crypto.FromECDSAPub(pk))
	return h, nil
}

// compute f(x) x=hash(pk) bigInt s[i][j]
func (cnf *OsmConf) GetPkToBigInt(grpId string, smInx uint16) (*big.Int, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	h, err := cnf.getPkHash(grpId, smInx)
	if err != nil {
		return big.NewInt(0), err
	}
	return big.NewInt(0).SetBytes(h.Bytes()), nil
}

func (cnf *OsmConf) GetInxByNodeId(grpId string, id *discover.NodeID) (uint16, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	if id == nil {
		log.SyslogInfo("GetInxByNodeId id is null")
		panic("GetInxByNodeId id is null")
	}
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem {
		if *value.NodeId == *id {
			return value.Inx, nil
		}
	}

	panic(fmt.Sprintf("GetInxByNodeId not find index by nodeId, id:%v", id.String()))
}

func (cnf *OsmConf) GetXValueByNodeId(grpId string, id *discover.NodeID) (*big.Int, error) {
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	if id == nil {
		log.SyslogInfo("GetXValueByNodeId id is null")
		panic("GetXValueByNodeId id is null")
	}
	cnf.checkGrpId(grpId)
	index, _ := cnf.GetInxByNodeId(grpId, id)
	return cnf.GetXValueByIndex(grpId, index)
}

func (cnf *OsmConf) GetNodeIdByIndex(grpId string, index uint16) (*discover.NodeID, error) {
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem {
		if value.Inx == index {
			return value.NodeId, nil
		}
	}

	panic(fmt.Sprintf("node id not found, grpId = %v, index = %v", grpId, index))
}

func (cnf *OsmConf) GetXValueByIndex(grpId string, index uint16) (*big.Int, error) {
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	cnf.checkGrpId(grpId)

	ge, err := cnf.GetGrpItem(grpId, index)
	if err != nil {
		return big.NewInt(0), err
	} else {
		return ge.XValue, nil
	}
}

func (cnf *OsmConf) GetLeaderIndex(grpId string) (uint16, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	cnf.checkGrpId(grpId)
	return cnf.GrpInfoMap[grpId].LeaderInx, nil
}

func (cnf *OsmConf) GetPeersByGrpId(grpId string) ([]mpcprotocol.PeerInfo, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	cnf.checkGrpId(grpId)
	peers := make([]mpcprotocol.PeerInfo, 0)
	grpElems, _ := cnf.GetGrpElems(grpId)
	for _, grpElem := range *grpElems {
		peers = append(peers, mpcprotocol.PeerInfo{PeerID: *grpElem.NodeId, Seed: 0})
	}
	return peers, nil
}

func (cnf *OsmConf) GetAllPeersNodeIds() ([]discover.NodeID, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	nodeIdsMap := make(map[discover.NodeID]interface{})
	nodeIds := make([]discover.NodeID, 0)

	for _, grpInfo := range cnf.GrpInfoMap {

		grpElems, _ := cnf.GetGrpElems(grpInfo.GrpId)
		for _, grpElem := range *grpElems {
			nodeIdsMap[*grpElem.NodeId] = nil
		}
	}

	for key, _ := range nodeIdsMap {
		nodeIds = append(nodeIds, key)
	}
	return nodeIds, nil
}

func (cnf *OsmConf) IsLeader(grpId string) (bool, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	cnf.checkGrpId(grpId)
	selfIndex, err := cnf.GetSelfInx(grpId)
	if err != nil {
		return false, err
	}
	leaderInx, err := cnf.GetLeaderIndex(grpId)
	if err != nil {
		return false, err
	}
	return selfIndex == leaderInx, nil

}

//////////////////////////////////util/////////////////////////////

// intersection
func Intersect(slice1, slice2 []uint16) []uint16 {
	m := make(map[uint16]int)
	ret := make([]uint16, 0)
	for _, v := range slice1 {
		m[v]++
	}

	for _, v := range slice2 {
		times, _ := m[v]
		if times == 1 {
			ret = append(ret, v)
		}
	}
	return ret
}

// s1-s2
// s2 must be the sub of s1
func Difference(slice1, slice2 []uint16) []uint16 {
	m := make(map[uint16]int)
	ret := make([]uint16, 0)
	inter := Intersect(slice1, slice2)
	for _, v := range inter {
		m[v]++
	}

	for _, value := range slice1 {
		times, _ := m[value]
		if times == 0 {
			ret = append(ret, value)
		}
	}
	return ret
}

func pkToAddr(PkBytes []byte) (common.Address, error) {
	if len(PkBytes) != schnorrmpc.PkLength {
		return common.Address{}, errors.New("invalid pk address in osmconf.go")
	}
	pk := crypto.ToECDSAPub(PkBytes[:])
	address := crypto.PubkeyToAddress(*pk)
	return address, nil
}

func GetGrpId(mpcResult mpcprotocol.MpcResultInterface) ([]byte, string, error) {
	if mpcResult == nil {
		log.SyslogErr("GetGrpId error", "error", "mpcresult is nil")
		return []byte{}, "", errors.New("in function GetGrpId mpcresult is nil")
	}
	grpId, err := mpcResult.GetByteValue(mpcprotocol.MpcGrpId)
	if err != nil {
		log.SyslogErr("GetGrpId error", "error", err.Error())
		return []byte{}, "", err
	}

	grpIdString := hexutil.Encode(grpId)
	return grpId, grpIdString, nil
}

func BuildDataByIndexes(indexes *[]big.Int) (*big.Int, error) {

	if indexes == nil {
		log.SyslogErr("BuildDataByIndexes indexes is null")
		return schnorrmpc.BigZero, errors.New("invalid point")
	}

	ret := schnorrmpc.BigZero
	bigTm := big.NewInt(0)
	bigTm.Add(schnorrmpc.BigOne, schnorrmpc.BigOne)

	for _, indexBig := range *indexes {
		bigTm1 := big.NewInt(0)
		bigTm1.Exp(bigTm, &indexBig, nil)
		ret = big.NewInt(0).Add(ret, bigTm1)
	}
	return ret, nil
}

func BuildStrByIndexes(indexes *[]big.Int) (string, error) {

	if indexes == nil {
		log.SyslogErr("BuildStringByIndexes indexes is null")
		return "", errors.New("invalid point")
	}

	var buf bytes.Buffer

	for _, indexBig := range *indexes {
		buf.WriteString(hexutil.Encode(indexBig.Bytes()))
	}
	return buf.String(), nil
}

func InterSecByIndexes(indexes *[]big.Int) (*big.Int, error) {
	if indexes == nil {
		log.SyslogErr("BuildDataByIndexes indexes is null")
		return schnorrmpc.BigZero, errors.New("invalid point")
	}
	if len(*indexes) == 0 {
		return nil, errors.New("no indexes needed to be intersected")
	}
	var ret *big.Int
	ret = &(*indexes)[0]

	for i := 1; i < len(*indexes); i++ {
		ret.And(ret, &(*indexes)[i])
	}
	return ret, nil
}

func IsHaming(sendCol *big.Int, smIndex uint16) (bool, error) {
	if sendCol == nil {
		return false, nil
	}

	b := sendCol.Bit(int(smIndex))
	return b == uint(1), nil
}

//////////////// test only begin///////////////

func (cnf *OsmConf) GetPrivateShare() (big.Int, error) {
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()

	nodeId, _ := cnf.GetSelfNodeId()
	if hexutil.Encode((*nodeId)[:]) == "0x9c6d6f351a3ede10ed994f7f6b754b391745bba7677b74063ff1c58597ad52095df8e95f736d42033eee568dfa94c5a7689a9b83cc33bf919ff6763ae7f46f8d" {
		return *big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x37b1af24c261773b711293c76564896ea3dacf5da54ba3a1d9f5f6d8feff3b"))), nil
	}

	if hexutil.Encode((*nodeId)[:]) == "0x78f760cd286c36c5db44c590f9e2409411e41f0bd10d17b6d4fb208cddf8df9b6957a027ee3b628fb685501cad256fefdc103916e2418e0ec9cee4883bbe4e4d" {
		return *big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x4f60631f7273a4bc9b056f01b6414291c09ac3e3365e4804e697937edf79b303"))), nil
	}

	if hexutil.Encode((*nodeId)[:]) == "0xdc997644bc12df6da60fef4922e257dc74bd506a05be714fb1380d1031c3eac102085bcc676339aa95b38502a6788ae6e4db329903e92d1a70be7e207c38ad35" {
		return *big.NewInt(0).SetBytes(hexutil.MustDecode(string("0xaeb934491f9706d38b2a74ccf4658041b1127d1c3dd344cbc9b30425f7fc45a8"))), nil
	}

	if hexutil.Encode((*nodeId)[:]) == "0x005d55b8634d6afa930b0a8c31a3cc2c8246d996ed06fb41d2520a4d8155eefa41258440ee2bfff2473191e62495729b9ef86d7be685ac21fd67d71b09cce1a5" {
		return *big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x51607e6ae0111434e813c1ae72c70222d6e5216f375c75ca09a888ee77861380"))), nil
	}
	return big.Int{}, nil
}

//////////////// test only end///////////////
