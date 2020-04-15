package osmconf

import (
	"crypto/ecdsa"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
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
	grpElms [...]GrpElem
}

type OsmConf struct {
	grpId string
	leaderInx uint16
	grpInfoMap map[string]ArrayGrpElem
	wrLock	sync.RWMutex
}

func NewOsmConf() (ret *OsmConf, err error){
	if osmConf == nil {
		// todo initialization
	}
	return nil, nil
}

func GetNewOsmConf() (*OsmConf){
	return osmConf
}

// todo rw lock
// get working pk
func (cnf *OsmConf) GetPK(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	return nil,nil
}

// todo rw lock
// get gpk share (public share)
func (cnf *OsmConf) GetPKShare(grpId string, smInx uint16) (*ecdsa.PublicKey, error){
	return nil,nil
}

// todo rw lock
func (cnf *OsmConf) LoadCnf(confPath string) error {
	return nil
}

// todo rw lock
func (cnf *OsmConf) FreshCnf(confPath string) error {
	return nil
}
// todo rw lock
func (cnf *OsmConf) GetSelfPrvKey() (*ecdsa.PrivateKey, error){
	return nil, nil
}

// todo rw lock
func (cnf *OsmConf) GetSelfInx(grpId string)(uint16, error){
	return 0, nil
}

// todo rw lock
func (cnf *OsmConf) GetGrpElems(grpId string)(*ArrayGrpElem, error){
	return nil, nil
}
// todo rw lock
func (cnf *OsmConf) GetGrpItem(grpId string, smInx uint16)(*GrpElem, error){
	return nil, nil
}