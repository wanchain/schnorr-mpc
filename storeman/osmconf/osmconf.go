package osmconf

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"io/ioutil"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
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
	wrLock	sync.RWMutex
}


//-----------------------configure content begin ---------------------------------
type GrpElemCotent struct {
	Inx string						`json:"index"`
	WorkingPk string			`json:"workingPk"`
	NodeId	string			`json:"nodeId"`
	PkShare	string			`json:"pkShare"`
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

	//defer cnf.wrLock.RUnlock()

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
	//cnf.wrLock.RLock()
	//cnf.wrLock.RUnlock()
	return nil
}

// todo rw lock
func (cnf *OsmConf) FreshCnf(confPath string) error {
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil
}

// todo rw lock
func (cnf *OsmConf) GetThresholdNum()(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return 3, nil
}

// todo rw lock
func (cnf *OsmConf) GetTotalNum()(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return 4, nil
}

//-----------------------get pk ---------------------------------
// todo rw lock
// get working pk
func (cnf *OsmConf) GetPK(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil,nil
}

func (cnf *OsmConf) GetPKByNodeId(grpId string, nodeId *discover.NodeID) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil,nil
}

// todo rw lock
// get gpk share (public share)
func (cnf *OsmConf) GetPKShare(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil,nil
}

func (cnf *OsmConf) GetPKShareByNodeId(grpId string, nodeId *discover.NodeID) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil,nil
}

//-----------------------get self---------------------------------
// todo rw lock
func (cnf *OsmConf) GetSelfPrvKey() (*ecdsa.PrivateKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil, nil
}

func (cnf *OsmConf) GetSelfPubKey() (*ecdsa.PublicKey, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetSelfInx(grpId string)(uint16, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return 0, nil
}

func (cnf *OsmConf) GetSelfNodeId()(*discover.NodeID, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return &discover.NodeID{}, nil
}

//-----------------------get group---------------------------------
// todo rw lock
func (cnf *OsmConf) GetGrpElemsInxes(grpId string)(*ArrayGrpElemsInx, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil, nil
}

func (cnf *OsmConf) GetGrpElems(grpId string)(*ArrayGrpElem, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil, nil
}

func (cnf *OsmConf) GetGrpInxes(grpId string)(*ArrayGrpElemsInx, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpItem(grpId string, smInx uint16)(*GrpElem, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpInxByGpk(gpk hexutil.Bytes)(string, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	grpId := "groupId1"
	return grpId, nil
}


//-----------------------others ---------------------------------
// todo rw lock
// compute f(x) x=hash(pk)
func (cnf *OsmConf) getPkHash(grpId string, smInx uint16)(common.Hash, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return common.Hash{}, nil
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
	return 0, nil
}

func (cnf *OsmConf) GetXValueByNodeId(grpId string,id *discover.NodeID)(*big.Int, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return big.NewInt(0),nil
}

func (cnf *OsmConf) GetNodeIdByIndex(grpId string,index uint16)(*discover.NodeID, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return &discover.NodeID{},nil
}

func (cnf *OsmConf) GetXValueByIndex(grpId string,index uint16)(*big.Int, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return big.NewInt(0),nil
}

func (cnf *OsmConf) GetLeaderIndex(grpId string)(uint16, error){
	// get pk
	// get pkhash
	// get x = hash(pk)
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	return 0,nil
}

func (cnf *OsmConf) GetPeers(grpId string)([]mpcprotocol.PeerInfo, error){
	defer cnf.wrLock.RUnlock()
	cnf.wrLock.RLock()
	peers := []mpcprotocol.PeerInfo{}
	grpElems, _ := cnf.GetGrpElems(grpId)
	for _, grpElem := range *grpElems {
		peers = append(peers, mpcprotocol.PeerInfo{PeerID: *grpElem.NodeId, Seed: 0})
	}
	return peers, nil
}

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


