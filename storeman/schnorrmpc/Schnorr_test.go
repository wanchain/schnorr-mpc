package schnorrmpc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/wanchain/go-wanchain/common/hexutil"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/crypto"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"testing"
)

func TestSchnorr(t *testing.T) {

	// Number of storeman nodes
	const Nstm = 50

	// Threshold for storeman signature
	const Thres = 26

	// Polynomial degree for shamir secret sharing
	const Degree = Thres - 1

	// Generate storeman's public key and private key
	Pubkey := make([]*ecdsa.PublicKey, Nstm)
	Prikey := make([]*ecdsa.PrivateKey, Nstm)

	for i := 0; i < Nstm; i++ {
		Prikey[i], _ = ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		Pubkey[i] = &Prikey[i].PublicKey
	}

	// Fix the evaluation point: Hash(Pub[1]), Hash(Pub[2]), ..., Hash(Pub[Nr])
	x := make([]big.Int, Nstm)
	for i := 0; i < Nstm; i++ {
		x[i].SetBytes(crypto.Keccak256(crypto.FromECDSAPub(Pubkey[i])))
		x[i].Mod(&x[i], crypto.S256().Params().N)
	}

	//----------------------------------------------  Setup  ----------------------------------------------//
	// In this stage, the storeman nodes work together to generate the group public keys and get its own
	// group private key share

	// Each of storeman node generates a random si
	s := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		s[i], _ = rand.Int(rand.Reader, crypto.S256().Params().N)
	}

	// Each storeman node conducts the shamir secret sharing process
	poly := make([]mpcprotocol.Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			sshare[i][j] = evaluatePoly(poly[i], &x[j], Degree)
		}
	}

	// every storeman node sends the secret shares to other nodes in secret!
	// Attention! IN SECRET!

	// After receiving the secret shares, each node computes its group private key share
	gskshare := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		gskshare[i] = big.NewInt(0)
		for j := 0; j < Nstm; j++ {
			gskshare[i].Add(gskshare[i], &sshare[j][i])
		}
		gskshare[i].Mod(gskshare[i], crypto.S256().Params().N)
	}

	// Each storeman node publishes the scalar point of its group private key share
	gpkshare := make([]*ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {
		shareTemp := new(ecdsa.PublicKey)
		shareTemp.Curve = crypto.S256()

		shareTemp.X, shareTemp.Y = crypto.S256().ScalarBaseMult(gskshare[i].Bytes())

		//gpkshare[i].X, gpkshare[i].Y = crypto.S256().ScalarBaseMult(gskshare[i].Bytes())
		gpkshare[i] = shareTemp
	}

	// Each storeman node computes the group public key by Lagrange's polynomial interpolation
	gpk := lagrangeECC(gpkshare, x, Degree)

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, crypto.S256().Params().N)
	}

	poly1 := make([]mpcprotocol.Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			rrshare[i][j] = evaluatePoly(poly1[i], &x[j], Degree)
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
		rshare[i].Mod(rshare[i], crypto.S256().Params().N)
	}

	// Compute the scalar point of r
	rpkshare := make([]*ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {

		shareTemp := new(ecdsa.PublicKey)
		shareTemp.Curve = crypto.S256()

		shareTemp.X, shareTemp.Y = crypto.S256().ScalarBaseMult(rshare[i].Bytes())

		rpkshare[i] = shareTemp
	}

	rpk := lagrangeECC(rpkshare, x, Degree)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	buffer.Write([]byte("wanchain"))
	buffer.Write(crypto.FromECDSAPub(rpk))

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

	ssG := new(ecdsa.PublicKey)
	ssG.X, ssG.Y = crypto.S256().ScalarBaseMult(ss.Bytes())

	mgpk := new(ecdsa.PublicKey)
	mgpk.X, mgpk.Y = crypto.S256().ScalarMult(gpk.X, gpk.Y, m.Bytes())

	temp := new(ecdsa.PublicKey)
	temp.X, temp.Y = crypto.S256().Add(mgpk.X, mgpk.Y, rpk.X, rpk.Y)

	if ssG.X.Cmp(temp.X) == 0 && ssG.Y.Cmp(temp.Y) == 0 {
		fmt.Println("Verification Succeeded")
		fmt.Println(" ", ssG.X)
		fmt.Println(" ", ssG.Y)
		fmt.Println(" ", temp.X)
		fmt.Println(" ", temp.Y)
	} else {
		t.Fatal("Verification Failed")
	}

	// compute gpk-> address address
	address := crypto.PubkeyToAddress(*gpk)
	// compute address'  (ssG - R)*m^ = pk'
	// temp1 = -R
	temp1 := new(ecdsa.PublicKey)
	temp1.Curve = crypto.S256()

	temp1.X = rpk.X
	temp1.Y = big.NewInt(0).Neg(rpk.Y)

	// temp2 = (-R) + ssG
	temp2 := new(ecdsa.PublicKey)
	temp2.Curve = crypto.S256()
	temp2.X, temp2.Y = crypto.S256().Add(temp1.X, temp1.Y, ssG.X, ssG.Y)

	// temp3 = temp2 * m^
	mInverse, ok := crypto.ModInverse(m, crypto.Secp256k1_N)
	if ok == false {
		t.Fatal("Verification Failed with address")
	}
	//
	temp3 := new(ecdsa.PublicKey)
	temp3.Curve = crypto.S256()
	temp3.X, temp3.Y = crypto.S256().ScalarMult(temp2.X, temp2.Y, mInverse.Bytes())

	// pk' -> address'
	address1 := crypto.PubkeyToAddress(*temp3)

	// check   address == address'
	if address != address1 {
		t.Fatal("Verification Failed address ")
	} else {
		fmt.Println("Verification Succeeded with address")
	}
}

// create gpk for 4 nodes.
func TestSchnorrCreateGpk4Nodes(t *testing.T) {

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
		x[i].Mod(&x[i], crypto.S256().Params().N)
	}

	//----------------------------------------------  Setup  ----------------------------------------------//
	// In this stage, the storeman nodes work together to generate the group public keys and get its own
	// group private key share

	// Each of storeman node generates a random si
	s := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		s[i], _ = rand.Int(rand.Reader, crypto.S256().Params().N)
	}

	// Each storeman node conducts the shamir secret sharing process
	poly := make([]mpcprotocol.Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			sshare[i][j] = evaluatePoly(poly[i], &x[j], Degree)
		}
	}

	// every storeman node sends the secret shares to other nodes in secret!
	// Attention! IN SECRET!

	// After receiving the secret shares, each node computes its group private key share
	gskshare := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		gskshare[i] = big.NewInt(0)
		for j := 0; j < Nstm; j++ {
			gskshare[i].Add(gskshare[i], &sshare[j][i])
		}
		gskshare[i].Mod(gskshare[i], crypto.S256().Params().N)
	}

	// Each storeman node publishes the scalar point of its group private key share
	gpkshare := make([]*ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {
		shareTemp := new(ecdsa.PublicKey)
		shareTemp.Curve = crypto.S256()

		shareTemp.X, shareTemp.Y = crypto.S256().ScalarBaseMult(gskshare[i].Bytes())

		//gpkshare[i].X, gpkshare[i].Y = crypto.S256().ScalarBaseMult(gskshare[i].Bytes())
		gpkshare[i] = shareTemp
	}

	// Each storeman node computes the group public key by Lagrange's polynomial interpolation
	gpk := lagrangeECC(gpkshare, x, Degree)

	fmt.Printf("gpk: %v \n", hexutil.Encode(crypto.FromECDSAPub(gpk)))

	for i := 0; i < Nstm; i++ {
		fmt.Printf("x[%v]: %v \n", i, hexutil.Encode(x[i].Bytes()))
		fmt.Printf("gpkshare[%v]: %v \n", i, hexutil.Encode(crypto.FromECDSAPub(gpkshare[i])))
		fmt.Printf("gskshare[%v]: %v \n\n", i, hexutil.Encode(gskshare[i].Bytes()))
	}

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, crypto.S256().Params().N)
	}

	poly1 := make([]mpcprotocol.Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = randPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			rrshare[i][j] = evaluatePoly(poly1[i], &x[j], Degree)
		}
	}
}

func TestSchnorr3(t *testing.T) {

	pksString := "0x0477947c2048cefbeb637ca46d98a1992c8f0a832e288be5adb36bce9ffb7965deef0024de93f1c30255a6b7deec2ba09d14f0c2f457416098b8266bb16a67e52004e84e2ab12f974cea11c948d276ce38b75638907f3259e8c60db07cf80b492d7da5a4c6e915ab16ba695a9825e6e4441cc843016100534fbce9a7d947d290afc904d665dd602ca1bc43245843dd4721dc7e4509b89c0b94e4744366c4ec491e9aad6efde662ab34bc836724db7f8613ff9131986fc21338e0f2352134b7f915f3d80425e027d24a8c65c0264ae8afbc4218cdd72266f8f245017b8725ef730ad4e80884dd77fbac60297ff6cf5cf6cb130b03b4551605cb5fc85f23ad98a9c6ea24d204367763779f7857ff97a304042885516f70e215ba57852d2763692ea8c6be93a7af3551a2014f7d2a1174335ce69808c57b8dc3c8b2f4ae948696052d8b81034304f6c5c039d2dc4d70aad4baefec8e31a5cc9ebd628cda32da8ed770189cf0dee3d5d5688618ff76e46bd3d40b1aa68b122c5c73af09060c065900790c68ee535304eff4a83c31442c94afd04414d7d4a41ecc20dfd6c587b94fd6a0398555c5dacf350411dab79965e9ef184b443b711b666aa290cfb0e2c263a317be9d0d3ec79a049eb4a277716d47fb868daab644eb66f0fff79a931b483af19a11fb2d097d59c09e73d02d7de04f099f463f10a368334e5b94a618eb6dfd80cfa29f6d9c5832e4047f33a451cb89f81d03823b73bbcc3e3efcaddc015c5e2907d2d4a9535eb6ecf23790c8451554319cec0848b1043281fde3d656e4d89f4041718221ad91cbd71a04e6b755737ccb1afcf5a839869a6d6dab529d263796a06e839190b25a45b31c8696659dade33df0be779a2d3aa987810bcf85d45a7e4d905c3ecf0b977a5dfc9f044c9c5be87bd1f4b334b4a34eac2fac1fb45a248eb071a077fb65e725670fa2367a9ffdb79233769859d44511f01f17a8eb3ae5092c739f2f37d07d656c440cd4043c188a61cdf98bc160935134a039acf3bf1a76d5389841fe93e93317fae34bc15d26c76d926650944c1d8c696212d48691540b04a362ff9e710f8fba967fb58004e919ca4d9a9f59b925579c17fd27fddbf144259a64562051cd93f1672729c3cb24ef17632d7538aa0f49c44b591f26685d3e0edba529e8f868f091839802c037043680e14d808cb3d9f34243204b16f6cdaf172253100526b3a774bc5cb1cbd70d2f9f5f52793b5aeb8b2e22861be26f71ee762aed65b983910fcfe6cab00d4f1704e03eee5f2f37368d687350ee6088d5255263c145ac7c65d630a2d3d7f81452a7d474e5f92e76f0fafddec74e4b0cc65499a34965e6485e3474166a21d6262cbc0444ca736fcd0476b316701d4c636f4abe69bca60e9f66f80293d821fdf3549d604c45dabc802c75c68ff9de8dff63e946d62a44c99c108558addd4568f63cdc66047021ed3d4f2d75ec7dbbdb4fffd429f9784cd4781481b6bb03f80673190751f0cb5f4d690ded3c1cecd9181fab90ed34bec67c1af519caa36e8c24bdd6430901"
	pkString := "0x042bda949acb1f1d5e6a2952c928a0524ee088e79bb71be990274ad0d3884230544b0f95d167eef4f76962a5cf569dabc018d025d7494986f7f0b11af7f0bdcbf4"

	pksBytes, _ := hexutil.Decode(pksString)

	pkBytes, _ := hexutil.Decode(pkString)

	var h common.Hash
	h = sha256.Sum256(pkBytes[:])
	xValue := big.NewInt(0).SetBytes(h.Bytes())

	fmt.Printf(hexutil.Encode(xValue.Bytes()))
	fmt.Printf("\n")

	pkCount := len(pksString) / 130
	pks := make([]*ecdsa.PublicKey, pkCount)

	for i := 0; i < pkCount; i++ {
		onePkBytes := pksBytes[i*65 : (i+1)*65]
		pks[i] = crypto.ToECDSAPub(onePkBytes)
	}

	pkRet, _ := evalByPolyG(pks, uint16(pkCount-1), xValue)

	fmt.Printf(hexutil.Encode(crypto.FromECDSAPub(pkRet)))
}

func TestAdd(t *testing.T) {

	pkString1 := "0x042bda949acb1f1d5e6a2952c928a0524ee088e79bb71be990274ad0d3884230544b0f95d167eef4f76962a5cf569dabc018d025d7494986f7f0b11af7f0bdcbf4"
	//pkString2 := "0x042bda949acb1f1d5e6a2952c928a0524ee088e79bb71be990274ad0d3884230544b0f95d167eef4f76962a5cf569dabc018d025d7494986f7f0b11af7f0bdcbf4"
	pkString2 := "0x0450149508a7d30e250357b991f4601be33f1880fb5e6181e60b203a10125648eec858e9db18ed354dc6a72d1fcbfba4a3986ffce6d938b3539c1ecc5568b09b9f"

	pkBytes, _ := hexutil.Decode(pkString1)
	pk1 := crypto.ToECDSAPub(pkBytes)

	pkBytes, _ = hexutil.Decode(pkString2)
	pk2 := crypto.ToECDSAPub(pkBytes)

	pk3, _ := add(pk1, pk2)
	fmt.Println(pk3)
}

func TestAdd2(t *testing.T) {
	// same point
	pkString1 := "0x042bda949acb1f1d5e6a2952c928a0524ee088e79bb71be990274ad0d3884230544b0f95d167eef4f76962a5cf569dabc018d025d7494986f7f0b11af7f0bdcbf4"
	pkString2 := "0x042bda949acb1f1d5e6a2952c928a0524ee088e79bb71be990274ad0d3884230544b0f95d167eef4f76962a5cf569dabc018d025d7494986f7f0b11af7f0bdcbf4"
	//pkString2 := "0x0450149508a7d30e250357b991f4601be33f1880fb5e6181e60b203a10125648eec858e9db18ed354dc6a72d1fcbfba4a3986ffce6d938b3539c1ecc5568b09b9f"

	pkBytes, _ := hexutil.Decode(pkString1)
	pk1 := crypto.ToECDSAPub(pkBytes)

	pkBytes, _ = hexutil.Decode(pkString2)
	pk2 := crypto.ToECDSAPub(pkBytes)

	smpcer := NewSkSchnorrMpc()
	//pt1,_:= smpcer.NewPt()
	//pt2,_:= smpcer.NewPt()

	pt, _ := smpcer.Add(pk1, pk2)
	fmt.Println(pt)
}

func TestAdd3(t *testing.T) {
	// Not same  point
	pkString1 := "0x042bda949acb1f1d5e6a2952c928a0524ee088e79bb71be990274ad0d3884230544b0f95d167eef4f76962a5cf569dabc018d025d7494986f7f0b11af7f0bdcbf4"
	pkString2 := "0x0450149508a7d30e250357b991f4601be33f1880fb5e6181e60b203a10125648eec858e9db18ed354dc6a72d1fcbfba4a3986ffce6d938b3539c1ecc5568b09b9f"

	pkBytes, _ := hexutil.Decode(pkString1)
	pk1 := crypto.ToECDSAPub(pkBytes)

	pkBytes, _ = hexutil.Decode(pkString2)
	pk2 := crypto.ToECDSAPub(pkBytes)

	smpcer := NewSkSchnorrMpc()

	pt, _ := smpcer.Add(pk1, pk2)
	fmt.Println(pt)
}
