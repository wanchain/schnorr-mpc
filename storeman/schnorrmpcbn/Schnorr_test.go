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
	for i := 0; i < Nstm; i++ {
		h := sha256.Sum256(crypto.FromECDSAPub(Pubkey[i]))
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
		fmt.Printf("x[%v]: %v \n", i, hexutil.Encode(x[i].Bytes()))
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
