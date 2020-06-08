package protocol

import (
	"fmt"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
)

type SendData struct {
	PKBytes hexutil.Bytes `json:"pk"`
	//Data    []byte        `json:"data"`
	//Data   string `json:"data"`
	Data   hexutil.Bytes `json:"data"`
	Extern string        `json:extern`
}

func (d *SendData) String() string {
	return fmt.Sprintf(
		"From:%s", hexutil.Encode([]byte(d.Data[:])))
}

type SignedResult struct {
	R hexutil.Bytes `json:"R"`
	S hexutil.Bytes `json:"S"`
}

type SendTxArgs struct {
	From      common.Address  `json:"from"`
	To        *common.Address `json:"to"`
	Gas       *hexutil.Big    `json:"gas"`
	GasPrice  *hexutil.Big    `json:"gasPrice"`
	Value     *hexutil.Big    `json:"value"`
	Data      hexutil.Bytes   `json:"data"`
	Nonce     *hexutil.Uint64 `json:"nonce"`
	ChainType string          `json:"chainType"` // 'WAN' or 'ETH'
	ChainID   *hexutil.Big    `json:"chainID"`
	SignType  string          `json:"signType"` //input 'hash' for hash sign (r,s,v), else for full sign(rawTransaction)
}

func (tx *SendTxArgs) String() string {
	return fmt.Sprintf(
		"From:%s, To:%s, Gas:%s, GasPrice:%s, Value:%s, Data:%s, Nonce:%d, ChainType:%s, ChainID:%s, SignType:%s",
		tx.From.String(),
		tx.To.String(),
		tx.Gas.String(),
		tx.GasPrice.String(),
		tx.Value.String(),
		common.ToHex(tx.Data),
		*tx.Nonce,
		tx.ChainType,
		tx.ChainID.String(),
		tx.SignType)
}
