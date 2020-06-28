package protocol

import (
	"fmt"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
)

type SendData struct {
	PKBytes hexutil.Bytes `json:"pk"`
	Data    hexutil.Bytes `json:"data"`
	Curve   hexutil.Bytes `json:"curve"`
	Extern  string        `json:extern`
}

func (d *SendData) String() string {
	return fmt.Sprintf(
		"From:%s", hexutil.Encode([]byte(d.Data[:])))
}

type SignedResult struct {
	R hexutil.Bytes `json:"R"`
	S hexutil.Bytes `json:"S"`

	// -1: internal error
	// 0: success
	// 1: rNW
	// 2: sNW
	// 3. rSlsh
	// 4. sSlsh

	ResultType uint8
	GrpId      hexutil.Bytes `json:"GrpId"`

	// uint256, one bit, one sm index
	IncntData hexutil.Bytes `json:"IncntData"`
	RNW       hexutil.Bytes `json:"RNW"`
	SNW       hexutil.Bytes `json:"SNW"`
	RSlsh     []RSlshPrf    `json:"RSlsh"`
	SSlsh     []SSlshPrf    `json:"SSlsh"`
}
