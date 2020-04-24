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
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"io/ioutil"
	"math/big"
	"strconv"
	"sync"
)

var osmConf *OsmConf

type GrpElem struct {
	Inx uint16
	WorkingPk *ecdsa.PublicKey
	NodeId	*discover.NodeID
	PkShare	*ecdsa.PublicKey
}

type ArrayGrpElem []GrpElem

type ArrayGrpElemsInx []uint16

type GrpInfoItem struct {
	GrpId		string
	GrpGpkBytes	hexutil.Bytes
	LeaderInx uint16
	TotalNum  uint16
	ThresholdNum uint16
	ArrGrpElems ArrayGrpElem
}

type OsmConf struct {
	GrpInfoMap map[string]GrpInfoItem
	SelfNodeId *discover.NodeID
	GpkPassword string
	WorkingPassword string
	AccMng	*accounts.Manager
	wrLock	sync.RWMutex
}


//-----------------------configure content begin ---------------------------------
type GrpElemCotent struct {
	Inx string						`json:"index"`
	WorkingPk hexutil.Bytes				`json:"workingPk"`
	NodeId	hexutil.Bytes					`json:"nodeId"`
	PkShare	hexutil.Bytes					`json:"pkShare"`
}

type GrpInfoItemContent struct {
	GrpId		string			`json:"grpId"`
	GrpPk	hexutil.Bytes		`json:"grpPk"`
	LeaderInx string			`json:"leaderInx"`
	TotalNumber  string			`json:"totalNumber"`
	ThresholdNumber string		`json:"thresholdNumber"`
	GrpElms  []GrpElemCotent	`json:"grpElms"`
}


type OsmFileContent struct {
	GrpInfo []GrpInfoItemContent
}

//-----------------------configure content end ---------------------------------

func NewOsmConf() (ret *OsmConf, err error){
	if osmConf == nil {
		// todo initialization
		osmConf = new(OsmConf)
		return osmConf, nil
	}
	return osmConf, nil
}

func GetOsmConf() (*OsmConf){
	return osmConf
}


//-----------------------mange config file ---------------------------------
// todo rw lock
func (cnf *OsmConf) LoadCnf(confPath string) error {

	defer cnf.wrLock.Unlock()

	ofcContent := OsmFileContent{}

	filePath := "/home/jacob/storemans.json"
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("LoadCnf error:%v",err.Error())
		panic(err.Error())
	}
	errUnmarshal := json.Unmarshal(b, &ofcContent)
	if errUnmarshal != nil {
		panic(errUnmarshal)
	}

	fmt.Printf("===========%v\n",ofcContent)

	// save configure file content to the OsmConf struct.
	cnf.wrLock.Lock()
	cnf.GrpInfoMap = make(map[string]GrpInfoItem, len(ofcContent.GrpInfo))
	for _, grpInfo := range ofcContent.GrpInfo{
		gii := GrpInfoItem{}

		gii.GrpId = grpInfo.GrpId

		gii.GrpGpkBytes = grpInfo.GrpPk

		leaderIndex,_ := strconv.Atoi(grpInfo.LeaderInx)
		gii.LeaderInx = uint16(leaderIndex)

		TotalNum,_ := strconv.Atoi(grpInfo.TotalNumber)
		gii.TotalNum = uint16(TotalNum)

		ThresholdNum,_ := strconv.Atoi(grpInfo.ThresholdNumber)
		gii.ThresholdNum = uint16(ThresholdNum)

		gii.ArrGrpElems = make(ArrayGrpElem,len(grpInfo.GrpElms))

		for i, ge := range grpInfo.GrpElms {

			Inx,_ := strconv.Atoi(ge.Inx)
			gii.ArrGrpElems[i].Inx = uint16(Inx)
			gii.ArrGrpElems[i].PkShare = crypto.ToECDSAPub(ge.PkShare)
			gii.ArrGrpElems[i].WorkingPk = crypto.ToECDSAPub(ge.WorkingPk)

			nodeId := discover.NodeID{}
			copy(nodeId[:],ge.NodeId[:])
			gii.ArrGrpElems[i].NodeId = &nodeId

		}

		cnf.GrpInfoMap[grpInfo.GrpId] = gii
	}
	return nil
}

// todo rw lock
func (cnf *OsmConf) FreshCnf(confPath string) error {
	return cnf.LoadCnf(confPath)
}

// todo rw lock
func (cnf *OsmConf) GetThresholdNum(grpId string)(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return cnf.GrpInfoMap[grpId].ThresholdNum,nil
}

// todo rw lock
func (cnf *OsmConf) GetTotalNum(grpId string)(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	cnf.wrLock.RLock()
	return cnf.GrpInfoMap[grpId].TotalNum,nil
}

//-----------------------get pk ---------------------------------
// todo rw lock
// get working pk
func (cnf *OsmConf) GetPK(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem{
		if value.Inx == smInx {
			return value.WorkingPk, nil
		}
	}
	return nil,nil
}

func (cnf *OsmConf) GetPKByNodeId(grpId string, nodeId *discover.NodeID) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem{
		if *value.NodeId == *nodeId {
			return value.WorkingPk, nil
		}
	}
	return nil,nil

}

// todo rw lock
// get gpk share (public share)
func (cnf *OsmConf) GetPKShare(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem{
		if value.Inx == smInx {
			return value.PkShare, nil
		}
	}

	return nil,nil
}

func (cnf *OsmConf) GetPKShareByNodeId(grpId string, nodeId *discover.NodeID) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem{
		if *value.NodeId == *nodeId {
			return value.PkShare, nil
		}
	}
	return nil,nil
}

//-----------------------get self---------------------------------
// todo rw lock


// todo ///////////////////////////////////////////////////self////////////////
func (cnf *OsmConf) GetSelfPubKey() (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	for _, grpInfo := range cnf.GrpInfoMap{
		for _, grpElem := range grpInfo.ArrGrpElems{
			if *grpElem.NodeId == *cnf.SelfNodeId{
				return grpElem.WorkingPk, nil
			}
		}
	}
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetSelfInx(grpId string)(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return cnf.GetInxByNodeId(grpId,cnf.SelfNodeId)
}

func (cnf *OsmConf) GetSelfNodeId()(*discover.NodeID, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return cnf.SelfNodeId,nil
}

func (cnf *OsmConf) GetSelfPrvKey() (*ecdsa.PrivateKey,error) {
	pk, _ := cnf.GetSelfPubKey()
	address, err := pkToAddr(crypto.FromECDSAPub(pk))
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
	keyjson, err = ioutil.ReadFile(account.URL.Path)

	if err != nil {
		// get account keyjson fail
		panic("find account from keystore fail")
		return nil, err
	}

	key, err := keystore.DecryptKey(keyjson, cnf.WorkingPassword)
	if err != nil {
		// decrypt account keyjson fail
		panic("find account from keystore fail")
		return nil, err
	}
	return key.PrivateKey,nil
}

func (cnf *OsmConf) SetSelfNodeId(id *discover.NodeID)(error){
	defer cnf.wrLock.Unlock()
	cnf.wrLock.Lock()
	cnf.SelfNodeId = id
	return nil
}

func (cnf *OsmConf) SetPassword(pwd string)(error){
	cnf.WorkingPassword = pwd
	cnf.GpkPassword = pwd
	return nil
}

func (cnf *OsmConf) SetAccountManger(accMng *accounts.Manager)(error){
	cnf.AccMng = accMng
	return nil
}

// todo ///////////////////////////////////////////////////self////////////////

//-----------------------get group---------------------------------
// todo rw lock
func (cnf *OsmConf) GetGrpElemsInxes(grpId string)(*ArrayGrpElemsInx, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	ret := make(ArrayGrpElemsInx,len(cnf.GrpInfoMap[grpId].ArrGrpElems))
	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for index, value := range arrGrpElem{
		ret[index] = value.Inx
	}
	return &ret, nil
}

func (cnf *OsmConf) GetGrpElems(grpId string)(*ArrayGrpElem, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	ArrayGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	return &ArrayGrpElem,nil

}

// todo rw lock
func (cnf *OsmConf) GetGrpItem(grpId string, smInx uint16)(*GrpElem, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	return &(arrGrpElem[smInx]),nil


	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpInxByGpk(gpk hexutil.Bytes)(string, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	for index, value := range cnf.GrpInfoMap{

		if bytes.Compare(value.GrpGpkBytes, gpk) == 0 {
			return index, nil
		}

	}
	return "",nil
}


//-----------------------others ---------------------------------
// todo rw lock
// compute f(x) x=hash(pk)
func (cnf *OsmConf) getPkHash(grpId string, smInx uint16)(common.Hash, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	pk,_ := cnf.GetPK(grpId,smInx)
	h:= sha256.Sum256(crypto.FromECDSAPub(pk))
	return h, nil
}

// todo rw lock
// compute f(x) x=hash(pk) bigInt s[i][j]
func (cnf *OsmConf) GetPkToBigInt(grpId string, smInx uint16)(*big.Int, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	h, err := cnf.getPkHash(grpId,smInx)
	if err != nil {
		return big.NewInt(0), err
	}
	return big.NewInt(0).SetBytes(h.Bytes()), nil
}

func (cnf *OsmConf) GetInxByNodeId(grpId string,id *discover.NodeID)(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem{
		if *value.NodeId == *id {
			return value.Inx, nil
		}
	}

	return 0, nil
}

func (cnf *OsmConf) GetXValueByNodeId(grpId string,id *discover.NodeID)(*big.Int, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	index,_ := cnf.GetInxByNodeId(grpId,id)
	return cnf.GetXValueByIndex(grpId,index)
}

func (cnf *OsmConf) GetNodeIdByIndex(grpId string,index uint16)(*discover.NodeID, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()

	arrGrpElem := cnf.GrpInfoMap[grpId].ArrGrpElems
	for _, value := range arrGrpElem{
		if value.Inx == index {
			return value.NodeId, nil
		}
	}

	return &discover.NodeID{},nil
}

func (cnf *OsmConf) GetXValueByIndex(grpId string,index uint16)(*big.Int, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return cnf.GetPkToBigInt(grpId,index)
}

func (cnf *OsmConf) GetLeaderIndex(grpId string)(uint16, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return cnf.GrpInfoMap[grpId].LeaderInx,nil
}

func (cnf *OsmConf) GetPeersByGrpId(grpId string)([]mpcprotocol.PeerInfo, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	peers := []mpcprotocol.PeerInfo{}
	grpElems, _ := cnf.GetGrpElems(grpId)
	for _, grpElem := range *grpElems {
		peers = append(peers, mpcprotocol.PeerInfo{PeerID: *grpElem.NodeId, Seed: 0})
	}
	return peers, nil
}

func (cnf *OsmConf) GetAllPeersNodeIds(grpId string)([]discover.NodeID, error){
	defer cnf.wrLock.RUnlock()

	cnf.wrLock.RLock()
	nodeIdsMap := make(map[discover.NodeID]interface{})
	nodeIds := []discover.NodeID{}

	for _,grpInfo := range cnf.GrpInfoMap{

		grpElems, _ := cnf.GetGrpElems(grpInfo.GrpId)
		for _, grpElem := range *grpElems {
			nodeIdsMap[*grpElem.NodeId] = nil
		}
	}

	for key, _ := range nodeIdsMap {
		nodeIds = append(nodeIds,key)
	}
	return nodeIds, nil
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
	if len(PkBytes) != 65 {
		return common.Address{}, errors.New("invalid pk address")
	}
	pk := crypto.ToECDSAPub(PkBytes[:])
	address := crypto.PubkeyToAddress(*pk)
	return address, nil
}

