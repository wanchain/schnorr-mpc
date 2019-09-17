package crypto

import (
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/core/types"
	"math/big"
)

type MPCTxSigner interface {
	Hash(tx *types.Transaction) common.Hash
	SignTransaction(tx *types.Transaction, R *big.Int, S *big.Int, V *big.Int) ([]byte, common.Address, error)
}
