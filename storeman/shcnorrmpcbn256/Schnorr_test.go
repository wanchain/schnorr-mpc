package shcnorrmpcbn256

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
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
		Pubkey[i] = *Pub
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
	poly := make([]Polynomial, Nstm)

	var sshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly[i] = RandPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			sshare[i][j] = EvaluatePoly(poly[i], &x[j], Degree) // share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
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

	gpk := LagrangeECC(gpkshare, x, Degree)

	//----------------------------------------------  Signing ----------------------------------------------//

	// 1st step: each storeman node decides a random number r using shamir secret sharing

	rr := make([]*big.Int, Nstm)

	for i := 0; i < Nstm; i++ {
		rr[i], _ = rand.Int(rand.Reader, bn256.Order)
	}

	poly1 := make([]Polynomial, Nstm)

	var rrshare [Nstm][Nstm]big.Int

	for i := 0; i < Nstm; i++ {
		poly1[i] = RandPoly(Degree, *s[i]) // fi(x), set si as its constant term
		for j := 0; j < Nstm; j++ {
			rrshare[i][j] = EvaluatePoly(poly1[i], &x[j], Degree) // share for j is fi(x) evaluation result on x[j]=Hash(Pub[j])
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

	rpk := LagrangeECC(rpkshare, x, Degree)

	// Forming the m: hash(message||rpk)
	var buffer bytes.Buffer
	buffer.Write([]byte("wanchain"))
	buffer.Write(rpk.Marshal())

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

	ssG := new(bn256.G1).ScalarBaseMult(&ss)

	mgpk := new(bn256.G1).ScalarMult(&gpk, m)

	temp := new(bn256.G1).Add(mgpk, &rpk)

	if CompareG1(*ssG, *temp) {
		fmt.Println("Verification Succeeded")
		fmt.Println(" ", ssG.Marshal())
		fmt.Println(" ", temp.Marshal())
	} else {
		t.Fatal("Verification Failed")
	}

}
