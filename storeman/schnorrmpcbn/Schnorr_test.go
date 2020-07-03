package schnorrmpcbn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/crypto/bn256/cloudflare"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"testing"
)

func TestSchnorr(t *testing.T) {

	// Number of storeman nodes
	const Nstm = 50

	// Threshold for schnorr signature
	const Thres = 26

	// Polynomial degree for shamir secret sharing
	const Degree = Thres - 1

	// Generate storeman's public key and private key.
	// Attention! These public keys use a different elliptic curve and have nothing to do with their wan accounts
	Pubkey := make([]bn256.G1, Nstm)
	Prikey := make([]big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		Pri, Pub, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Prikey[i] = *Pri
		fmt.Printf("Index i %d privkey %s\n", i, hexutil.Encode(Pri.Bytes()))
		Pubkey[i] = *Pub
		fmt.Printf("Index i %d Pubkey %s\n", i, Pubkey[i].String())
	}

	// Fix the evaluation point: Hash(Pub[1]), Hash(Pub[2]), ..., Hash(Pub[Nr])
	x := make([]big.Int, Nstm)
	for i := 0; i < Nstm; i++ {
		x[i].SetBytes(crypto.Keccak256(Pubkey[i].Marshal()))
		x[i].Mod(&x[i], bn256.Order)
	}

	//----------------------------------------------  Setup  ----------------------------------------------//
	// In this stage, the storeman nodes work together to generate the group public keys and get its own
	// group private key share

	// Each of storeman node generates a random si
	s := make([]*big.Int, Nstm)
	for i := 0; i < Nstm; i++ {
		s[i], _ = rand.Int(rand.Reader, bn256.Order)
	}

	// Each storeman node conducts the shamir secret sharing process
	poly := make([]mpcprotocol.Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			sshare[i][j] = evaluatePoly(poly[i], &x[j], Degree) // share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
		}
	}

	// every storeman node sends the secret shares to other nodes in secret!
	// Attention! IN SECRET!

	// After reveiving the secret shares, each node computes its group private key share
	gskshare := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		gskshare[i] = big.NewInt(0)
		for j := 0; j < Nstm; j++ {
			gskshare[i].Add(gskshare[i], &sshare[j][i])
		}
	}

	// Each storeman node publishs the scalar point of its group private key share
	gpkshare := make([]*bn256.G1, Nstm)

	for i := 0; i < Nstm; i++ {
		gpkshare[i] = new(bn256.G1).ScalarBaseMult(gskshare[i])
	}

	// Each storeman node computes the group public key by Lagrange's polynomial interpolation

	gpk := lagrangeECC(gpkshare, x, Degree)

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, bn256.Order)
	}

	poly1 := make([]mpcprotocol.Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			rrshare[i][j] = evaluatePoly(poly1[i], &x[j], Degree) // share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
		}
	}

	// every storeman node sends the secret shares to other nodes in secret!
	// Attention! IN SECRET!

	rshare := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rshare[i] = big.NewInt(0)
		for j := 0; j < Nstm; j++ {
			rshare[i].Add(rshare[i], &rrshare[j][i])
		}
	}

	// Compute the scalar point of r
	rpkshare := make([]*bn256.G1, Nstm)

	for i := 0; i < Nstm; i++ {
		rpkshare[i] = new(bn256.G1).ScalarBaseMult(rshare[i])
	}

	rpk := lagrangeECC(rpkshare, x, Degree)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	buffer.Write([]byte("wanchain"))
	buffer.Write(rpk.Marshal())

	//M := crypto.Keccak256(buffer.Bytes())
	M := sha256.Sum256(buffer.Bytes())
	m := new(big.Int).SetBytes(M[:])

	// Each storeman node computes the signature share
	sigshare := make([]big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		sigshare[i] = schnorrSign(*gskshare[i], *rshare[i], *m)
	}

	// Compute the signature using Lagrange's polynomial interpolation

	ss := lagrange(sigshare, x, Degree)

	// the final signature = (rpk,ss)

	//----------------------------------------------  Verification ----------------------------------------------//

	// check ssG = rpk + m*gpk

	ssG := new(bn256.G1).ScalarBaseMult(&ss)

	mgpk := new(bn256.G1).ScalarMult(gpk, m)

	temp := new(bn256.G1).Add(mgpk, rpk)

	if compareG1(ssG, temp) {
		fmt.Println("Verification Succeeded")
		fmt.Println(" ", ssG.Marshal())
		fmt.Println(" ", temp.Marshal())

		fmt.Printf(" ssG %s\n", hexutil.Encode(ssG.Marshal()))
		fmt.Printf(" temp %s\n", hexutil.Encode(temp.Marshal()))
	} else {
		t.Fatal("Verification Failed")
	}

	temp1 := new(bn256.G1)
	_, err := temp1.Unmarshal(temp.Marshal())
	if err != nil {
		t.Fatal(err.Error())
	}
	if compareG1(temp, temp1) {
		fmt.Println("Marshal success")
	} else {
		fmt.Println("Marshal fail")
	}

	if ok := temp1.IsOnCurve(); ok {
		fmt.Println("temp1 on Curve")
	} else {
		fmt.Println("temp1 Not on Curve")
	}
}

func TestSchnorrCreateGpk4NodesBN(t *testing.T) {

	// Number of storeman nodes
	const Nstm = 4

	// Threshold for storeman signature
	const Thres = 3

	// Polynomial degree for shamir secret sharing
	const Degree = Thres - 1

	const (
		pk0 = "0x0425fa6a4190ddc87d9f9dd986726cafb901e15c21aafd2ed729efed1200c73de89f1657726631d29733f4565a97dc00200b772b4bc2f123a01e582e7e56b80cf8"
		pk1 = "0x04be3b7fd88613dc272a36f4de570297f5f33b87c26de3060ad04e2ea697e13125a2454acd296e1879a7ddd0084d9e4e724fca9ef610b21420978476e2632a1782"
		pk2 = "0x0495e8fd461c37f1db5da62bfbee2ad305d77e57fbef917ec8109e6425e942fb60ddc28b1edfdbcda1aa5ace3160b458b9d3d5b1fe306b4d09a030302a08e2db93"
		pk3 = "0x04ccd16e96a70a5b496ff1cec869902b6a8ffa00715897937518f1c9299726f7090bc36cc23c1d028087eb0988c779663e996391f290631317fc22f84fa9bf2467"
	)
	// Generate storeman's public key and private key
	Pubkey := make([]*ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {
		Pubkey[i] = new(ecdsa.PublicKey)
		Pubkey[i].Curve = crypto.S256()
	}

	Pubkey[0] = crypto.ToECDSAPub(hexutil.MustDecode(pk0))
	Pubkey[1] = crypto.ToECDSAPub(hexutil.MustDecode(pk1))
	Pubkey[2] = crypto.ToECDSAPub(hexutil.MustDecode(pk2))
	Pubkey[3] = crypto.ToECDSAPub(hexutil.MustDecode(pk3))

	// Fix the evaluation point: Hash(Pub[1]), Hash(Pub[2]), ..., Hash(Pub[Nr])
	x := make([]big.Int, Nstm)
	y := make([]big.Int, Nstm)
	for i := 0; i < Nstm; i++ {
		h := sha256.Sum256(crypto.FromECDSAPub(Pubkey[i]))

		y[i].SetBytes(h[:])
		x[i].SetBytes(h[:])

		x[i].Mod(&x[i], bn256.Order)
	}

	//----------------------------------------------  Setup  ----------------------------------------------//
	// In this stage, the storeman nodes work together to generate the group public keys and get its own
	// group private key share

	// Each of storeman node generates a random si
	s := make([]*big.Int, Nstm)
	for i := 0; i < Nstm; i++ {
		s[i], _ = rand.Int(rand.Reader, bn256.Order)
	}

	// Each storeman node conducts the shamir secret sharing process
	poly := make([]mpcprotocol.Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			sshare[i][j] = evaluatePoly(poly[i], &x[j], Degree) // share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
		}
	}

	// every storeman node sends the secret shares to other nodes in secret!
	// Attention! IN SECRET!

	// After reveiving the secret shares, each node computes its group private key share
	gskshare := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		gskshare[i] = big.NewInt(0)
		for j := 0; j < Nstm; j++ {
			gskshare[i].Add(gskshare[i], &sshare[j][i])
		}
	}

	// Each storeman node publishs the scalar point of its group private key share
	gpkshare := make([]*bn256.G1, Nstm)

	for i := 0; i < Nstm; i++ {
		gpkshare[i] = new(bn256.G1).ScalarBaseMult(gskshare[i])
	}

	// Each storeman node computes the group public key by Lagrange's polynomial interpolation

	gpk := lagrangeECC(gpkshare, x, Degree)

	fmt.Printf("gpk: %v \n", hexutil.Encode(gpk.Marshal()))

	for i := 0; i < Nstm; i++ {
		fmt.Printf("workingPk[%v]:%v\n", i, hexutil.Encode(crypto.FromECDSAPub(Pubkey[i])))
		fmt.Printf("x[%v]: %v \n", i, hexutil.Encode(x[i].Bytes()))
		fmt.Printf("y[%v] before mod: %v \n", i, hexutil.Encode(y[i].Bytes()))
		fmt.Printf("gpkshare[%v]: %v \n", i, hexutil.Encode(gpkshare[i].Marshal()))
		fmt.Printf("gskshare[%v]: %v \n\n", i, hexutil.Encode(gskshare[i].Bytes()))
	}

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, bn256.Order)
	}

	poly1 := make([]mpcprotocol.Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			rrshare[i][j] = evaluatePoly(poly1[i], &x[j], Degree) // share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
		}
	}

	// every storeman node sends the secret shares to other nodes in secret!
	// Attention! IN SECRET!

	rshare := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rshare[i] = big.NewInt(0)
		for j := 0; j < Nstm; j++ {
			rshare[i].Add(rshare[i], &rrshare[j][i])
		}
	}

	// Compute the scalar point of r
	rpkshare := make([]*bn256.G1, Nstm)

	for i := 0; i < Nstm; i++ {
		rpkshare[i] = new(bn256.G1).ScalarBaseMult(rshare[i])
	}

	rpk := lagrangeECC(rpkshare, x, Degree)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	buffer.Write([]byte("wanchain"))
	buffer.Write(rpk.Marshal())

	M := crypto.Keccak256(buffer.Bytes())
	m := new(big.Int).SetBytes(M)

	// Each storeman node computes the signature share
	sigshare := make([]big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		sigshare[i] = schnorrSign(*gskshare[i], *rshare[i], *m)
	}

	// Compute the signature using Lagrange's polynomial interpolation

	ss := lagrange(sigshare, x, Degree)

	// the final signature = (rpk,ss)

	//----------------------------------------------  Verification ----------------------------------------------//

	// check ssG = rpk + m*gpk

	ssG := new(bn256.G1).ScalarBaseMult(&ss)

	mgpk := new(bn256.G1).ScalarMult(gpk, m)

	temp := new(bn256.G1).Add(mgpk, rpk)

	if compareG1(ssG, temp) {
		fmt.Println("Verification Succeeded")
		fmt.Println(" ", ssG.Marshal())
		fmt.Println(" ", temp.Marshal())

		fmt.Printf(" ssG %s\n", hexutil.Encode(ssG.Marshal()))
		fmt.Printf(" temp %s\n", hexutil.Encode(temp.Marshal()))
	} else {
		t.Fatal("Verification Failed")
	}
}

func TestBnSchnorrMpc_StringToPt(t *testing.T) {
	// errorstring
	ptStr := "0x0431c9258ad1f1600b80555476c88c23be67ddc8cc48e75951158b18f59cf7716e27509d200d819eb2195fe532329eea84239ddc8d0e71fdfb3b4e3d3aae9ae487"
	smpcer := NewBnSchnorrMpc()

	pt, err := smpcer.StringToPt(ptStr)
	if err != nil {
		t.Error(err.Error())
	}
	fmt.Println(smpcer.PtToHexString(pt))
}

func TestBnSchnorrMpc_StringToPt2(t *testing.T) {
	// right string
	//ptStr := "0x12bb068ad8a169ce0eb77f186db2a2f545dfbca94fe5df77d4292936bda012f92ac4e753ad1b549c64645d23f0696ad49e5b6d621a1a3508c87ca82a75a02469"
	ptStr := "0x144e37ab4cbaa930a0b9fead55f234daec6fe406330754c940a579e448bb0d82013857d03e4460d856935757a864931f2ddff9be14235eb4f961b7174189a5a4"
	smpcer := NewBnSchnorrMpc()

	pt, err := smpcer.StringToPt(ptStr)
	if err != nil {
		t.Error(err.Error())
	}
	fmt.Println(smpcer.PtToHexString(pt))

	//rpk+m*gpk
	ptLeft, err := smpcer.StringToPt("0x163f69727c44bf76538bf4bfce3d77246915f2cd3098deb26234093f672903e606a9568c50b8bcd5c4f4333c313092bb98add44159448d91e3d3b850a4fb1ff9")
	//sg
	ptRight, err := smpcer.StringToPt("0x13375930578a8f7b4f4549d7d012175e65d7e0a59b7b5c70708740cf5491ef561656b8453cea7e65dfeb1b8156cd5adc73d3a6bfc4624c7e71686e2042b793f4")

	ret := smpcer.Equal(ptLeft, ptRight)
	if ret {
		fmt.Println("equal")
	} else {
		fmt.Println("Not equal")
	}
	fmt.Println("------------------------")
	ptLeftTemp, _ := ptLeft.(*bn256.G1)
	ptRightTemp, _ := ptRight.(*bn256.G1)

	fmt.Println("ptLeft", ptLeftTemp.String())
	fmt.Println("ptRight", ptRightTemp.String())

	fmt.Println("------------------------")
	fmt.Println("ptLeft", *ptLeftTemp)
	fmt.Println("ptRight", *ptRightTemp)

	fmt.Println("------------------------")
	fmt.Printf("left %#v\n", *ptLeftTemp)
	fmt.Printf("right %#v\n", *ptRightTemp)

	fmt.Println("------------------------")
	fmt.Println("ptLeft", smpcer.PtToHexString(ptLeft))
	fmt.Println("ptRight", smpcer.PtToHexString(ptRight))

}

func TestBnSchnorrMpc_SkG(t *testing.T) {
	prv0 := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x6934315acd94b49ecdff3c85b8e28191e3e98444e144a9e96d9057de5ddd74f1")))
	prv1 := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x74deabccc1bd2a0f26a4f13bd7db2e2d1aaf739065620d835548a7e84cb59395")))
	prv2 := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x83a65e1cbf9f059841e7fb672f7dcefedace8043f4fa035828f70901f735f814")))
	prv3 := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x83a5311e7e22376d66d96f34f64ddb9c18a71fb12c2b9a008f255efa3467c63c")))

	smpcer := NewBnSchnorrMpc()

	pt1, _ := smpcer.SkG(prv0)
	pt2, _ := smpcer.SkG(prv1)
	pt3, _ := smpcer.SkG(prv2)
	pt4, _ := smpcer.SkG(prv3)

	fmt.Println(smpcer.PtToHexString(pt1))
	fmt.Println(smpcer.PtToHexString(pt2))
	fmt.Println(smpcer.PtToHexString(pt3))
	fmt.Println(smpcer.PtToHexString(pt4))
}

func TestBnSchnorrMpc_MulPK(t *testing.T) {
	m := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x2d80340b58fdf74dc3f1e77051b6475d1df2ab0772f2360919923735d7aa1a3d")))

	smpcer := NewBnSchnorrMpc()

	gpkShare, err := smpcer.StringToPt("0x0adf29eaa11da6cb58f84b0e0bcdf7501e81b115a401dffd05ccbfa3373adb7e2b0d612ed449b7194b3333b7620551ec5221334ba1a39c8df2ec604fce76ea0c")
	rpkShare, err := smpcer.StringToPt("0x0ff360597812ad3f641e77e53ccdf219ca849eb2d03a22ed3d84ea8294214de923ef4706c272c766cb3abc7554703e76b1d8e373e5aed472e5d013bb06ef047a")
	if err != nil {
		t.Error(err.Error())
	}

	sshare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x2f9ce2b689d859ff9436f6e7e763dc44fa0e7951dc86e167eac969bc51f69eac")))

	SSG, _ := smpcer.SkG(sshare)

	mgpk, _ := smpcer.MulPK(m, gpkShare)

	pkTemp, _ := smpcer.Add(rpkShare, mgpk)

	fmt.Println(SSG.(*bn256.G1).String())
	fmt.Println(pkTemp.(*bn256.G1).String())
}

/*
ptLeft bn256.G1(19567b5dd54d410b53960a3c80b262cf03ac6f51229c54c005e1fedb5c6d7f71, 279af59fd8d2f90983becfe05c4a871dd831adf677d803d5705916c113b72c16)
ptRight bn256.G1(00af4e11252a42022eeff8fb983fa4bee7e1087762b12999c85669a557011b6e, 0466d47beb5169f1307729c25085f7dac71160b976e0eaac7fdff73c733416f2)
*/

func TestCurveMod(t *testing.T) {
	pBig0 := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x6934315acd94b49ecdff3c85b8e28191e3e98444e144a9e96d9057de5ddd74f1")))
	pBigRet := big.NewInt(0).Mod(pBig0, bn256.Order)

	fmt.Println(hexutil.Encode(pBig0.Bytes()))
	fmt.Println(hexutil.Encode(pBigRet.Bytes()))
}

func TestBnSchnorrMpc_SchnorrSign(t *testing.T) {
	// compute s  s = rskshare + m*gskShare

	// compute sg
	// compute rpk+m*gpkShare
	m := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x017d11cab3e1fd0907aef0f92e6f259e4525d69bd3bb90b5ed4cda7eb3726391")))
	rskShare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x245f002dcbec5eeda87ccfacd8d33cacd2f49ad78b5654d4628c3bb5923f0934")))
	gskShare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x83a65e1cbf9f059841e7fb672f7dcefedace8043f4fa035828f70901f735f814")))
	sshare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x1db26eaba26e3f85f5f058d2a9554226d37b440f4579d09b6c2e37696e85e0e8")))

	gpkShareStr := "0x0adf29eaa11da6cb58f84b0e0bcdf7501e81b115a401dffd05ccbfa3373adb7e2b0d612ed449b7194b3333b7620551ec5221334ba1a39c8df2ec604fce76ea0c"
	rpkShareStr := "0x0847b0f51bbb842c6c9b8b43badd4ad480c23b6f80364ca72cae8c590559c51f14a18578c674f634d1d7f41e1347d2b7e4f9295de43cd7b4d6d3c60e17dc4117"

	smpcer := NewBnSchnorrMpc()

	gpkShare, err := smpcer.StringToPt(gpkShareStr)
	if err != nil {
		t.Fatal(err.Error())
	}
	rpkShare, err := smpcer.StringToPt(rpkShareStr)
	if err != nil {
		t.Fatal(err.Error())
	}

	gpkShare1, err := smpcer.SkG(gskShare)
	if err != nil {
		t.Fatal(err.Error())
	}

	rpkShare1, err := smpcer.SkG(rskShare)
	if err != nil {
		t.Fatal(err.Error())
	}

	fmt.Println("---------------------------------gpkShare1 compare")
	if smpcer.Equal(gpkShare1, gpkShare) {
		fmt.Println("gpkShare1 equal")
	} else {
		fmt.Println("gpkShare1 Not equal")
	}

	fmt.Println("---------------------------------rpkShare1 compare")
	if smpcer.Equal(rpkShare1, rpkShare) {
		fmt.Println("rpkShare1 equal")
	} else {
		fmt.Println("rpkShare1 Not equal")
	}

	fmt.Println("m", hexutil.Encode(m.Bytes()))

	big1 := big.NewInt(1).Mul(m, gskShare)
	bigmgsk := big1.Mod(big1, bn256.Order)

	sshare1 := big.NewInt(0).Add(rskShare, big1)
	sshare1.Mod(sshare1, bn256.Order)

	sshare2 := schnorrSign(*gskShare, *rskShare, *m)

	fmt.Println("---------------------------------sshare compare")
	fmt.Println("sshare1", hexutil.Encode(sshare1.Bytes()))
	fmt.Println("sshare2", hexutil.Encode(sshare2.Bytes()))
	fmt.Println("sshare", hexutil.Encode(sshare.Bytes()))
	fmt.Println("bigmgsk", hexutil.Encode(bigmgsk.Bytes()))
	fmt.Println("big1", hexutil.Encode(big1.Bytes()))

	if sshare1.Cmp(sshare) == 0 {
		fmt.Println("sshare1 equal")
	} else {
		fmt.Println("sshare1 not equal")

	}

	SSG, err := smpcer.SkG(sshare1)
	if err != nil {
		t.Fatal(err.Error())
	}

	mgpk, err := smpcer.MulPK(m, gpkShare)
	if err != nil {
		t.Fatal(err.Error())
	}

	mgpk1, err := smpcer.SkG(big1)
	if err != nil {
		t.Fatal(err.Error())
	}
	fmt.Println("---------------------------------mgpk1 compare")
	if smpcer.Equal(mgpk1, mgpk) {
		fmt.Println("mgpk1 equal")
	} else {
		fmt.Println("mgpk1 NOT equal")
	}

	pkTemp, err := smpcer.Add(rpkShare, mgpk)
	if err != nil {
		t.Fatal(err.Error())
	}

	fmt.Println("SSG(string)", SSG.(*bn256.G1).String())
	fmt.Println("rpk+mgpk string", pkTemp.(*bn256.G1).String())
	fmt.Println("---------------------------------after compute")
	fmt.Println("after rpkShare", smpcer.PtToHexString(rpkShare))
	fmt.Println("after gpkShare", smpcer.PtToHexString(gpkShare))
	fmt.Println("after m", hexutil.Encode(m.Bytes()))

	if smpcer.Equal(SSG, pkTemp) {
		fmt.Println("sucess")
	} else {
		fmt.Println("fail")
		t.Fatal("fail")
	}

}

func TestBnSchnorrMpc_SchnorrSign1(t *testing.T) {
	// compute s  s = rskshare + m*gskShare

	// compute sg
	// compute rpk+m*gpkShare
	m := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x017d11cab3e1fd0907aef0f92e6f259e4525d69bd3bb90b5ed4cda7eb3726391")))
	rskShare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x245f002dcbec5eeda87ccfacd8d33cacd2f49ad78b5654d4628c3bb5923f0934")))
	gskShare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x83a65e1cbf9f059841e7fb672f7dcefedace8043f4fa035828f70901f735f814")))
	sshare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x1db26eaba26e3f85f5f058d2a9554226d37b440f4579d09b6c2e37696e85e0e8")))

	//gpkShareStr := "0x0adf29eaa11da6cb58f84b0e0bcdf7501e81b115a401dffd05ccbfa3373adb7e2b0d612ed449b7194b3333b7620551ec5221334ba1a39c8df2ec604fce76ea0c"
	//rpkShareStr := "0x0847b0f51bbb842c6c9b8b43badd4ad480c23b6f80364ca72cae8c590559c51f14a18578c674f634d1d7f41e1347d2b7e4f9295de43cd7b4d6d3c60e17dc4117"
	//
	//smpcer := NewBnSchnorrMpc()

	bigSshareJacob := big.NewInt(1).Mul(m, gskShare)
	bigSshareJacob = bigSshareJacob.Add(bigSshareJacob, rskShare)
	bigSshareJacob.Mod(bigSshareJacob, bn256.Order)

	if bigSshareJacob.Cmp(sshare) == 0 {
		t.Log("sshare right")
	} else {
		t.Error("sshare Not right")
	}

	sgJacob := new(bn256.G1).ScalarBaseMult(bigSshareJacob)

	gpkShare := new(bn256.G1).ScalarBaseMult(gskShare)
	fmt.Println("gpkShare", gpkShare.String())
	rpkShare := new(bn256.G1).ScalarBaseMult(rskShare)
	fmt.Println("rpkShare", rpkShare.String())
	mgpkShare := new(bn256.G1).ScalarMult(gpkShare, m)
	fmt.Println("mgpkShare", mgpkShare.String())

	sum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	sum = sum.Add(rpkShare, mgpkShare)
	fmt.Println("sum", sum.String())
	fmt.Println("sgJacob", sgJacob.String())
	if sum.String() == sgJacob.String() {
		t.Log("success")
	} else {
		t.Fatal("fail")
	}
}

func TestBnSchnorrMpc_SchnorrSign3(t *testing.T) {
	// compute s  s = rskshare + m*gskShare

	// compute sg
	// compute rpk+m*gpkShare
	m := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x017d11cab3e1fd0907aef0f92e6f259e4525d69bd3bb90b5ed4cda7eb3726391")))
	rskShare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x245f002dcbec5eeda87ccfacd8d33cacd2f49ad78b5654d4628c3bb5923f0934")))
	gskShare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x83a65e1cbf9f059841e7fb672f7dcefedace8043f4fa035828f70901f735f814")))
	sshare := big.NewInt(0).SetBytes(hexutil.MustDecode(string("0x1db26eaba26e3f85f5f058d2a9554226d37b440f4579d09b6c2e37696e85e0e8")))

	//gpkShareStr := "0x0adf29eaa11da6cb58f84b0e0bcdf7501e81b115a401dffd05ccbfa3373adb7e2b0d612ed449b7194b3333b7620551ec5221334ba1a39c8df2ec604fce76ea0c"
	//rpkShareStr := "0x0847b0f51bbb842c6c9b8b43badd4ad480c23b6f80364ca72cae8c590559c51f14a18578c674f634d1d7f41e1347d2b7e4f9295de43cd7b4d6d3c60e17dc4117"
	//
	//smpcer := NewBnSchnorrMpc()

	bigSshareJacob := big.NewInt(1).Mul(m, gskShare)
	bigSshareJacob = bigSshareJacob.Add(bigSshareJacob, rskShare)
	bigSshareJacob.Mod(bigSshareJacob, bn256.Order)
	if bigSshareJacob.Cmp(sshare) == 0 {
		t.Log("sshare right")
	} else {
		t.Error("sshare Not right")
	}

	smpcer := NewBnSchnorrMpc()
	rpkShare, _ := smpcer.SkG(rskShare)
	gpkShare, _ := smpcer.SkG(gskShare)
	fmt.Println("gpkShare", smpcer.PtToHexString(gpkShare))
	mgpkShare, _ := smpcer.MulPK(m, gpkShare)
	fmt.Println("rpkShare", smpcer.PtToHexString(rpkShare))
	fmt.Println("mgpkShare", smpcer.PtToHexString(mgpkShare))

	sum, _ := smpcer.Add(rpkShare, mgpkShare)
	fmt.Println("sum", smpcer.PtToHexString(sum))
	sgJacob, _ := smpcer.SkG(sshare)
	fmt.Println("sgJacob", smpcer.PtToHexString(sgJacob))
	if smpcer.Equal(sgJacob, sum) {
		t.Log("success")
	} else {
		t.Fatal("fail")
	}
}
