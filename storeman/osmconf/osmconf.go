package osmconf

import (
	"crypto/ecdsa"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
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
	GrpGpkBytes	hexutil.Bytes
	LeaderInx uint16
	ArrGrpElems ArrayGrpElem
}

type OsmConf struct {
	GrpInfoMap map[string]GrpInfoItem
	wrLock	sync.RWMutex
}


func NewOsmConf() (ret *OsmConf, err error){
	if osmConf == nil {
		// todo initialization
	}
	return nil, nil
}

func GetOsmConf() (*OsmConf){
	return osmConf
}

//-----------------------mange config file ---------------------------------

// todo rw lock
func (cnf *OsmConf) LoadCnf(confPath string) error {
	defer cnf.wrLock.Unlock()
	return nil
}

// todo rw lock
func (cnf *OsmConf) FreshCnf(confPath string) error {
	defer cnf.wrLock.Unlock()
	return nil
}

// todo rw lock
func (cnf *OsmConf) GetThresholdNum()(uint16, error){
	defer cnf.wrLock.Unlock()
	return 3, nil
}

// todo rw lock
func (cnf *OsmConf) GetTotalNum()(uint16, error){
	defer cnf.wrLock.Unlock()
	return 4, nil
}

//-----------------------get pk ---------------------------------
// todo rw lock
// get working pk
func (cnf *OsmConf) GetPK(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.Unlock()
	return nil,nil
}

// todo rw lock
// get gpk share (public share)
func (cnf *OsmConf) GetPKShare(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	defer cnf.wrLock.Unlock()
	return nil,nil
}


//-----------------------get self---------------------------------
// todo rw lock
func (cnf *OsmConf) GetSelfPrvKey() (*ecdsa.PrivateKey, error){
	defer cnf.wrLock.Unlock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetSelfInx(grpId string)(uint16, error){
	defer cnf.wrLock.Unlock()
	return 0, nil
}

//-----------------------get group---------------------------------
// todo rw lock
func (cnf *OsmConf) GetGrpElemsInxes(grpId string)(*ArrayGrpElemsInx, error){
	defer cnf.wrLock.Unlock()
	return nil, nil
}

func (cnf *OsmConf) GetGrpElems(grpId string)(*ArrayGrpElem, error){
	defer cnf.wrLock.Unlock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpItem(grpId string, smInx uint16)(*GrpElem, error){
	defer cnf.wrLock.Unlock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpInxByGpk(gpk hexutil.Bytes)(string, error){
	defer cnf.wrLock.Unlock()
	grpId := "groupId1"
	return grpId, nil
}


//-----------------------others ---------------------------------
// todo rw lock
// compute f(x) x=hash(pk)
func (cnf *OsmConf) getPkHash(grpId string, smInx uint16)(common.Hash, error){
	defer cnf.wrLock.Unlock()
	return common.Hash{}, nil
}

// todo rw lock
// compute f(x) x=hash(pk) bigInt s[i][j]
func (cnf *OsmConf) GetPkToBigInt(grpId string, smInx uint16)(*big.Int, error){
	h, err := cnf.getPkHash(grpId,smInx)
	if err != nil {
		return big.NewInt(0), err
	}
	return big.NewInt(0).SetBytes(h.Bytes()), nil
}

func (cnf *OsmConf) GetInxByNodeId(grpId string,id *discover.NodeID)(uint16, error){
	return 0, nil
}

func (cnf *OsmConf) GetPeers(grpId string)([]mpcprotocol.PeerInfo, error){

	peers := []mpcprotocol.PeerInfo{}
	grpElems, _ := cnf.GetGrpElems(grpId)
	for _, grpElem := range *grpElems {
		peers = append(peers, mpcprotocol.PeerInfo{PeerID: *grpElem.NodeId, Seed: 0})
	}
	return peers, nil
}


