package schnorrmpcbn

import (
	"bytes"
	"crypto/rand"
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

	mgpk := new(bn256.G1).ScalarMult(&gpk, m)

	temp := new(bn256.G1).Add(mgpk, &rpk)

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
