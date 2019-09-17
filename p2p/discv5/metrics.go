package discv5

import "github.com/wanchain/schnorr-mpc/metrics"

var (
	ingressTrafficMeter = metrics.NewMeter("discv5/InboundTraffic")
	egressTrafficMeter  = metrics.NewMeter("discv5/OutboundTraffic")
)
