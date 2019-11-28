package protocol

import (
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
)

type SendData struct {
	PKBytes  hexutil.Bytes `json:"pk"`
	SignType hexutil.Bytes `json:signType` // 0: sec256 1: bn256
	//Data    []byte        `json:"data"`
	//Data   string `json:"data"`
	Data   hexutil.Bytes `json:"data"`
	Extern string        `json:extern`
}

type CreateGPKArg struct {
	SignType hexutil.Bytes `json:signType` // 0: sec256 1: bn256
}

func (d *SendData) String() string {
	return fmt.Sprintf(
		"From:%s", hexutil.Encode([]byte(d.Data[:])))
}

type SignedResult struct {
	R hexutil.Bytes `json:"R"`
	S hexutil.Bytes `json:"S"`
}
