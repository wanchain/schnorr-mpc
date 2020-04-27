package osmconf

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"testing"
)

const configFilePath = "/home/jacob/mpc_test_1/data1/groupInfo.json"
const selfNodeId = "0x9c6d6f351a3ede10ed994f7f6b754b391745bba7677b74063ff1c58597ad52095df8e95f736d42033eee568dfa94c5a7689a9b83cc33bf919ff6763ae7f46f8d"
const pwd = "123456"

func TestGetOsmConf(t *testing.T) {
	osf := GetOsmConf()
	if osf != nil {
		fmt.Printf("error osf shoud be nil")
	}
}

func TestAll(t *testing.T) {
	osm := GetOsmConf()
	osm.SetFilePath(configFilePath)
	osm.LoadCnf(configFilePath)
	var nodeId discover.NodeID
	copy(nodeId[:],hexutil.MustDecode(selfNodeId))

	// set nodeId
	osm.SetSelfNodeId(&nodeId)
	prv,_ := osm.GetSelfPrvKey()

	// set pwd
	osm.SetPassword(pwd)

	pk := new(ecdsa.PublicKey)
	pk.Curve = crypto.S256()
	pk.X,pk.Y = prv.PublicKey.X,prv.PublicKey.Y

	fmt.Printf(hexutil.Encode(crypto.FromECDSAPub(pk)))
}

func TestIntersect(t *testing.T) {
	s1 := []uint16{1,2,3,4}
	s2 := []uint16{2,3,4,5,6,7}

	s := Intersect(s1,s2)
	fmt.Printf("%v",s)
}

func TestDifference(t *testing.T) {
	s1 := []uint16{1,2,3,4}
	s2 := []uint16{2,3,4,5,6,7}

	s := Difference(s1,s2)
	fmt.Printf("%v\n",s)

	s = Difference(s2,s1)
	fmt.Printf("%v\n",s)

	s = Difference(s1,s1)
	fmt.Printf("%v\n",s)
}