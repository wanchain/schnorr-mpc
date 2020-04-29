package schnorrmpc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/wanchain/go-wanchain/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
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
	poly := make([]Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = RandPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			sshare[i][j] = EvaluatePoly(poly[i], &x[j], Degree)
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
	gpkshare := make([]ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {
		gpkshare[i].X, gpkshare[i].Y = crypto.S256().ScalarBaseMult(gskshare[i].Bytes())
	}

	// Each storeman node computes the group public key by Lagrange's polynomial interpolation
	gpk := LagrangeECC(gpkshare, x, Degree)

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, crypto.S256().Params().N)
	}

	poly1 := make([]Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = RandPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			rrshare[i][j] = EvaluatePoly(poly1[i], &x[j], Degree)
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
	rpkshare := make([]ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {
		rpkshare[i].X, rpkshare[i].Y = crypto.S256().ScalarBaseMult(rshare[i].Bytes())
	}

	rpk := LagrangeECC(rpkshare, x, Degree)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	buffer.Write([]byte("wanchain"))
	buffer.Write(crypto.FromECDSAPub(rpk))

	M := crypto.Keccak256(buffer.Bytes())
	m := new(big.Int).SetBytes(M)

	// Each storeman node computes the signature share
	sigshare := make([]big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		sigshare[i] = SchnorrSign(*gskshare[i], *rshare[i], *m)
	}

	// Compute the signature using Lagrange's polynomial interpolation

	ss := Lagrange(sigshare, x, Degree)

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
	mInverse, ok := crypto.ModInverse(m,crypto.Secp256k1_N)
	if ok == false{
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
	}else{
		fmt.Println("Verification Succeeded with address")
	}
}
// create gpk for 4 nodes.
func TestSchnorr2(t *testing.T) {

	// Number of storeman nodes
	const Nstm = 4

	// Threshold for storeman signature
	const Thres = 2

	// Polynomial degree for shamir secret sharing
	const Degree = Thres - 1

	const (
		pk0 = "0x04d9482a01dd8bb0fb997561e734823d6cf341557ab117b7f0de72530c5e2f0913ef74ac187589ed90a2b9b69f736af4b9f87c68ae34c550a60f4499e2559cbfa5"
		pk1 = "0x043d0461abc005e082021fb2dd81781f676941b2f922422932d56374646328a8132bb0f7956532981bced30a1aa3301e9134041b399058de31d388651fc005b49e"
		pk2 = "0x04f65f08b31c46e97751865b24a176f28888f2cef91ffdf95d0cbf3fd71b4abdab7f4b4b55cfac5853198854569bad590ed260557f50e6bc944ad63a274369339a"
		pk3 = "0x042687ff2d4ba1cfa8bbd27aa33d691dabe007a0eaaf109aab2a990154906f00860e5ead9ed95080c144a61a0eabb5df7f109ff348c9b9de68ee133a49c0731fc0"
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
		//x[i].Mod(&x[i], crypto.S256().Params().N)
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
	poly := make([]Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = RandPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			sshare[i][j] = EvaluatePoly(poly[i], &x[j], Degree)
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
	gpkshare := make([]ecdsa.PublicKey, Nstm)

	for i := 0; i < Nstm; i++ {
		gpkshare[i].X, gpkshare[i].Y = crypto.S256().ScalarBaseMult(gskshare[i].Bytes())
	}

	// Each storeman node computes the group public key by Lagrange's polynomial interpolation
	gpk := LagrangeECC(gpkshare, x, Degree)

	fmt.Printf("gpk: %v \n",hexutil.Encode(crypto.FromECDSAPub(gpk)))

	for i := 0; i < Nstm; i++ {
		fmt.Printf("x[%v]: %v \n",i,hexutil.Encode(x[i].Bytes()))
		fmt.Printf("gpkshare[%v]: %v \n",i,hexutil.Encode(crypto.FromECDSAPub(&gpkshare[i])))
		fmt.Printf("gskshare[%v]: %v \n\n",i,hexutil.Encode(gskshare[i].Bytes()))
	}

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, crypto.S256().Params().N)
	}

	poly1 := make([]Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = RandPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			// share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
			rrshare[i][j] = EvaluatePoly(poly1[i], &x[j], Degree)
		}
	}
}
