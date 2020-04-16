package osmconf

import (
	"crypto/ecdsa"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"math/big"
	"sync"
)

var osmConf *OsmConf

type GrpElem struct {
	inx uint16
	workingPk *ecdsa.PublicKey
	nodeId	*discover.NodeID
	pkShare	*ecdsa.PublicKey
}

type ArrayGrpElem struct {
	grpElms []GrpElem
}

type ArrayGrpElemsInx struct {
	indxes  []uint16
}

type GrpInfoItem struct {
	grpGpkBytes	hexutil.Bytes
	leaderInx uint16
	arrayGrpElems ArrayGrpElem
}

type OsmConf struct {
	grpInfoMap map[string]GrpInfoItem
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
func (cnf *OsmConf) GetSelfPrvKey() (*ecdsa.PrivateKey, error){
	defer cnf.wrLock.Unlock()
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetSelfInx(grpId string)(uint16, error){
	defer cnf.wrLock.Unlock()
	return 0, nil
}

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
// compute f(x) x=hash(pk)
func (cnf *OsmConf) GetPkHash(grpId string, smInx uint16)(common.Hash, error){
	defer cnf.wrLock.Unlock()
	return common.Hash{}, nil
}

// todo rw lock
// compute f(x) x=hash(pk) bigInt s[i][j]
func (cnf *OsmConf) GetPkToBigInt(grpId string, smInx uint16)(*big.Int, error){
	defer cnf.wrLock.Unlock()
	return big.NewInt(0), nil
}

// todo rw lock
func (cnf *OsmConf) GetTotalNum()(uint16, error){
	defer cnf.wrLock.Unlock()
	return 4, nil
}

// todo rw lock
func (cnf *OsmConf) GetThresholdNum()(uint16, error){
	defer cnf.wrLock.Unlock()
	return 3, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpInxByGpk(gpk hexutil.Bytes)(string, error){
	defer cnf.wrLock.Unlock()
	grpId := "groupId1"
	return grpId, nil
}

func (cnf *OsmConf) GetInxByNodeId(grpId string,id *discover.NodeID)(uint16, error){
	return 0, nil
}