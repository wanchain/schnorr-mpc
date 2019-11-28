package shcnorrmpcbn256

import (
	"github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
)

var bigZero = big.NewInt(0)

var bigOne = big.NewInt(1)

// Generator of ECC
var gbase = new(bn256.G1).ScalarBaseMult(big.NewInt(int64(1)))

// Structure defination for polynomial
type Polynomial []big.Int
