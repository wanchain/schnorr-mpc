package osmconf

import (
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpcbn"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"testing"
)

const configFilePath = "/home/jacob/mpc_poc/groupInfo_multicurve.json"
const KeystoreDir = "/home/jacob/mpc_poc/data1/keystore"

//const selfNodeId = "0xed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb737e23980bdd11fa86f5d824ea1f8a35333ac6f99246464dd4d19adac9da21d1"
const selfNodeId = "0xe6d15450a252e2209574a98585785a79c160746fa282a8ab9d4658c381093928eda1f03e70606dd4eee6402389c619ac9f725c63e5b80b947730d31152ce6612"
const pwdPath = "/home/jacob/mpc_poc/data1/pwd"

const pwd = "123456"

func TestGetOsmConf(t *testing.T) {
	osf := GetOsmConf()
	if osf != nil {
		fmt.Printf("error osf shoud be nil")
	}
}

func TestLoadCnf(t *testing.T) {
	osm := GetOsmConf()
	osm.SetFilePath(configFilePath)
	osm.LoadCnf(configFilePath)
	fmt.Printf("%#v\n", *osm)
}

func Initialize() {
	osm := GetOsmConf()
	osm.SetFilePath(configFilePath)
	osm.LoadCnf(configFilePath)

	var nodeId discover.NodeID
	copy(nodeId[:], hexutil.MustDecode(selfNodeId))

	// set nodeId
	osm.SetSelfNodeId(&nodeId)

	osm.SetPwdPath(pwdPath)

}
func TestGetThresholdNum(t *testing.T) {

	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()
	thesholdNumber, err := osm.GetThresholdNum(grpId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Println("thesholdNumber", thesholdNumber)
}

func TestGetTotalNum(t *testing.T) {

	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()
	tn, err := osm.GetTotalNum(grpId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Println("GetTotalNum", tn)
}

func TestGetPk(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	pk, err := osm.GetPK(grpId, 0)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	if !pk.IsOnCurve(pk.X, pk.Y) {
		t.Fatalf("fail:%s", "Not on curve")
	}

}

func TestGetPKByNodeId(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	pk, err := osm.GetPKByNodeId(grpId, osm.SelfNodeId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	if !pk.IsOnCurve(pk.X, pk.Y) {
		t.Fatalf("fail:%s", "Not on curve")
	}

}

func TestGetPKShareBytes(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	pkBytes, err := osm.GetPKShareBytes(grpId, 0, mpcprotocol.SK256Curve)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}

	smpc := schnorrmpc.NewSkSchnorrMpc()
	pk, err := smpc.UnMarshPt(pkBytes)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	} else {
		fmt.Printf("pk share :%s\n", smpc.PtToHexString(pk))
	}

	pkBytes, err = osm.GetPKShareBytes(grpId, 0, mpcprotocol.BN256Curve)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}

	smpc1 := schnorrmpcbn.NewBnSchnorrMpc()
	pk1, err := smpc1.UnMarshPt(pkBytes)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	} else {
		fmt.Printf("pk share :%s\n", smpc1.PtToHexString(pk1))
	}

}

func TestGetSelfInx(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()
	selfIndex, err := osm.GetSelfInx(grpId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("selfIndex:%v\n", selfIndex)
}

func TestGetSelfNodeId(t *testing.T) {
	Initialize()

	osm := GetOsmConf()
	selfNodeId, err := osm.GetSelfNodeId()
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("selfNodeId:%v\n", selfNodeId.String())
}

func TestGetSelfPrvKey(t *testing.T) {
	Initialize()
	osm := GetOsmConf()

	am, _, err := makeAccountManagerMock(KeystoreDir)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	osm.SetAccountManger(am)
	selfNodeId := "0xed214e8ce499d92a2085e7e6041b4f081c7d29d8770057fc705a131d2918fcdb737e23980bdd11fa86f5d824ea1f8a35333ac6f99246464dd4d19adac9da21d1"

	var nodeId discover.NodeID
	copy(nodeId[:], hexutil.MustDecode(selfNodeId))
	osm.SetSelfNodeId(&nodeId)

	prv, err := osm.GetSelfPrvKey()
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}

	fmt.Printf("prvKey:%v\n", hexutil.Encode(prv.D.Bytes()))
}

func TestGetGrpElemsInxes(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()
	grpElemsInx, err := osm.GetGrpElemsInxes(grpId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("grpElemsInx:%v\n", *grpElemsInx)
}

func TestGetGrpElems(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()
	grpElems, err := osm.getGrpElems(grpId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("grpElems:%v\n", *grpElems)
}

func TestGetGrpInxByGpk(t *testing.T) {
	Initialize()

	osm := GetOsmConf()
	gpk1 := hexutil.MustDecode("0x04ee8797b2d53915708fb24cee7dbdddfa43eb2cbfa19cd427cdfd02d2169bb028e5dfa3514a92fa2eb4da42085bbc7807c1acb08f132c13b2951759d4281ece8b")
	gpk2 := hexutil.MustDecode("0x2ab2e3655ebd58b188f9ed3ba466e3ae39f4f6e9bcbe80e355be8f1ccd222f97175ebb6b000cb43a3aa6e69dd05d1710719559b17983a0067420de99f3c3cd9f")

	grpStr1, err := osm.GetGrpInxByGpk(gpk1)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("grpStr1:%v\n", grpStr1)

	grpStr2, err := osm.GetGrpInxByGpk(gpk2)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("grpStr2:%v\n", grpStr2)
}

func TestGetInxByNodeId(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	nodeId := discover.NodeID{}
	copy(nodeId[:], hexutil.MustDecode(selfNodeId))
	index, err := osm.GetInxByNodeId(grpId, &nodeId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("index:%v\n", index)
}

func TestGetXValueByNodeId(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()
	nodeId := discover.NodeID{}
	copy(nodeId[:], hexutil.MustDecode(selfNodeId))

	xValue, err := osm.GetXValueByNodeId(grpId, &nodeId, schnorrmpcbn.NewBnSchnorrMpc())
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("xValue:%v\n", hexutil.Encode(xValue.Bytes()))

	xValue1, err := osm.GetXValueByNodeId(grpId, &nodeId, schnorrmpc.NewSkSchnorrMpc())
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("xValue1:%v\n", hexutil.Encode(xValue1.Bytes()))

}

func TestGetPeersByGrpId(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	peerInfo, err := osm.GetPeersByGrpId(grpId)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("peerInfo:%v\n", peerInfo)
}

func TestGetAllPeersNodeIds(t *testing.T) {
	Initialize()

	osm := GetOsmConf()

	peerInfo, err := osm.GetAllPeersNodeIds()
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("peerInfo:%v\n", peerInfo)
}

func TestGetNodeIdByIndex(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	nodeId, err := osm.GetNodeIdByIndex(grpId, 0)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("nodeId:%v\n", nodeId.String())

	nodeId1, err := osm.GetNodeIdByIndex(grpId, 1)
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("nodeId1:%v\n", nodeId1.String())

}

func TestGetXValueByIndex(t *testing.T) {
	Initialize()

	grpId := "0x0000000000000000000000000000000000000031353839393533323738313235"
	osm := GetOsmConf()

	xValue, err := osm.GetXValueByIndex(grpId, 0, schnorrmpcbn.NewBnSchnorrMpc())
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("xValue:%v\n", hexutil.Encode(xValue.Bytes()))

	xValue1, err := osm.GetXValueByIndex(grpId, 1, schnorrmpc.NewSkSchnorrMpc())
	if err != nil {
		t.Fatalf("fail:%s", err.Error())
	}
	fmt.Printf("xValue1:%v\n", hexutil.Encode(xValue1.Bytes()))

}

func TestIntersect(t *testing.T) {
	s1 := []uint16{1, 2, 3, 4}
	s2 := []uint16{2, 3, 4, 5, 6, 7}

	s := intersect(s1, s2)
	fmt.Printf("%v", s)
}

func TestDifference(t *testing.T) {
	s1 := []uint16{1, 2, 3, 4}
	s2 := []uint16{2, 3, 4, 5, 6, 7}

	s := Difference(s1, s2)
	fmt.Printf("%v\n", s)

	s = Difference(s2, s1)
	fmt.Printf("%v\n", s)

	s = Difference(s1, s1)
	fmt.Printf("%v\n", s)
}

func TestBuildDataByIndexes(t *testing.T) {
	big0 := big.Int{}
	bg1 := big.NewInt(1)
	bg2 := big.NewInt(2)
	bg3 := big.NewInt(3)

	bigs := []big.Int{big0, *bg1, *bg2, *bg3}
	ret, _ := BuildDataByIndexes(&bigs)

	fmt.Printf("%v", ret)
}

func TestSwitch(t *testing.T) {
	match := []int{1, 2}
	lenMatches := len(match)

	switch lenMatches {
	case 1:
		fmt.Printf("1")
	case 0:
		fmt.Printf("0")
	default:
		fmt.Printf("default")
	}
}

func TestInterSecByIndexes(t *testing.T) {
	bg0 := big.NewInt(0)
	bg1 := big.NewInt(1)
	bg2 := big.NewInt(2)
	bg3 := big.NewInt(3)

	bigs := []big.Int{*bg0, *bg1, *bg2, *bg3}
	ret, _ := BuildDataByIndexes(&bigs)

	fmt.Printf("%v\n", ret)

	bg20 := big.NewInt(2)
	bg30 := big.NewInt(3)

	bigs0 := []big.Int{*bg20, *bg30}
	ret0, _ := BuildDataByIndexes(&bigs0)

	fmt.Printf("%v\n", ret0)

	bigInter, _ := InterSecByIndexes(&([]big.Int{*ret, *ret0}))
	fmt.Printf("%v\n", bigInter)

	for i := 0; i < 16; i++ {
		b, _ := IsHaming(bigInter, uint16(i))
		if b {
			fmt.Printf("%v>>>>>>>>%v\n", i, b)
		}
	}
}
