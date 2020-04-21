package protocol

import (
	"github.com/wanchain/schnorr-mpc/common/hexutil"
)

// cm
type PolyCMInfo struct {
	PolyCM 				[]hexutil.Bytes	`json:"PolyCM"`	// poly degree 17, contains 18 points
	PolyCMR 			hexutil.Bytes `json:"PolyR"`
	PolyCMS 			hexutil.Bytes `json:"PolyS"`
}

// s[i][j]
type  PolyDataPln struct {
	PolyData		hexutil.Bytes	`json:"PolyData"`
	PolyDataR		hexutil.Bytes	`json:"PolyDataR"`
	PolyDataS		hexutil.Bytes	`json:"polyDataS"`
}

type RSlshProof struct {
	PolyCMInfo
	PolyDataPln
	Sndr			hexutil.Bytes
	Rcvr			hexutil.Bytes
}

type SSlshProof struct {
	PolyDataPln
	M			hexutil.Bytes    //m
	RPKShare	hexutil.Bytes    //sender's rpkshare
	GPKShare	hexutil.Bytes    //sender's gpkshare
	Sndr		hexutil.Bytes
	Rcvr		hexutil.Bytes
}