package protocol

import (
	"github.com/wanchain/schnorr-mpc/common/hexutil"
)

// cm
type PolyCMInfo struct {
	PolyCM 				hexutil.Bytes	`json:"PolyCM"`	// poly degree 17, contains 18 points
	PolyCMR 			hexutil.Bytes 	`json:"PolyCMR"`
	PolyCMS 			hexutil.Bytes 	`json:"PolyCMS"`
}

// s[i][j]
type  PolyDataPln struct {
	PolyData		hexutil.Bytes		`json:"PolyData"`
	PolyDataR		hexutil.Bytes		`json:"PolyDataR"`
	PolyDataS		hexutil.Bytes		`json:"PolyDataS"`
}


type RSlshPrf struct {
	PolyCMInfo
	PolyDataPln
	SndrAndRcvrIndex [2]uint8
	BecauseSndr			bool
}

type SSlshPrf struct {
	PolyDataPln
	M			hexutil.Bytes    //m
	RPKShare	hexutil.Bytes    //sender's rpkshare
	GPKShare	hexutil.Bytes    //sender's gpkshare
	SndrAndRcvrIndex [2]uint8
	BecauseSndr			bool
}