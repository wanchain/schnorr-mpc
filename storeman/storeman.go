package storeman

import (
	"context"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/rlp"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"os"

	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/wanchain/schnorr-mpc/accounts"
	"github.com/wanchain/schnorr-mpc/core/types"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/rpc"
	"github.com/wanchain/schnorr-mpc/storeman/btc"
	"github.com/wanchain/schnorr-mpc/storeman/storemanmpc"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"github.com/wanchain/schnorr-mpc/storeman/validator"
)

type Config struct {
	StoremanNodes     []*discover.Node
	Password          string
	DataPath          string
	SchnorrThreshold  int
	SchnorrTotalNodes int
}

var DefaultConfig = Config{
	StoremanNodes:     make([]*discover.Node, 0),
	SchnorrThreshold:  26,
	SchnorrTotalNodes: 50,
}

type StrmanKeepAlive struct {
	version   int
	magic     int
	recipient discover.NodeID
}

type StrmanKeepAliveOk struct {
	version int
	magic   int
	status  int
}

type StrmanAllPeers struct {
	Ip     []string
	Port   []string
	Nodeid []string
}

type StrmanGetPeers struct {
	LocalPort string
}

const keepaliveMagic = 0x33

// New creates a Whisper client ready to communicate through the Ethereum P2P network.
func New(cfg *Config, accountManager *accounts.Manager, aKID, secretKey, region string) *Storeman {
	storeman := &Storeman{
		peers:      make(map[discover.NodeID]*Peer),
		quit:       make(chan struct{}),
		cfg:        cfg,
		isSentPeer: false,
		peersPort:  make(map[discover.NodeID]string),
	}

	mpcprotocol.MpcSchnrThr = cfg.SchnorrThreshold
	mpcprotocol.MpcSchnrNodeNumber = cfg.SchnorrTotalNodes
	mpcprotocol.MPCDegree = mpcprotocol.MpcSchnrThr / 2 // 17/2 = 8

	if mpcprotocol.MpcSchnrNodeNumber < mpcprotocol.MpcSchnrThr {
		log.SyslogErr("should: SchnorrTotalNodes >= SchnorrThreshold")
		os.Exit(1)
	}
	log.Info("=========New storeman", "SchnorrThreshold", mpcprotocol.MpcSchnrThr)
	log.Info("=========New storeman", "SchnorrTotalNodes", mpcprotocol.MpcSchnrNodeNumber)
	log.Info("=========New storeman", "MPCDegree", mpcprotocol.MPCDegree)

	storeman.mpcDistributor = storemanmpc.CreateMpcDistributor(accountManager,
		storeman,
		aKID,
		secretKey,
		region,
		cfg.Password)

	dataPath := filepath.Join(cfg.DataPath, "storeman", "data")
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dataPath, 0700); err != nil {
			log.SyslogErr("make Storeman path fail", "err", err.Error())
		}
	}
	log.Info("==================================")
	log.Info("=========New storeman", "DB file path", dataPath)
	log.Info("==================================")
	validator.NewDatabase(dataPath)
	// p2p storeman sub protocol handler
	storeman.protocol = p2p.Protocol{
		Name:    mpcprotocol.PName,
		Version: uint(mpcprotocol.PVer),
		Length:  mpcprotocol.NumberOfMessageCodes,
		Run:     storeman.HandlePeer,
		NodeInfo: func() interface{} {
			return map[string]interface{}{
				"version": mpcprotocol.PVerStr,
			}
		},
	}

	return storeman
}

////////////////////////////////////
// Storeman
////////////////////////////////////
type Storeman struct {
	protocol       p2p.Protocol
	peers          map[discover.NodeID]*Peer
	storemanPeers  map[discover.NodeID]bool
	peerMu         sync.RWMutex  // Mutex to sync the active peer set
	quit           chan struct{} // Channel used for graceful exit
	mpcDistributor *storemanmpc.MpcDistributor
	cfg            *Config
	server         *p2p.Server
	isSentPeer     bool
	peersPort      map[discover.NodeID]string

	//allPeersConnected chan bool
}

// MaxMessageSize returns the maximum accepted message size.
func (sm *Storeman) MaxMessageSize() uint32 {
	// TODO what is the max size of storeman???
	return uint32(1024 * 1024)
}

func (sm *Storeman)getLeaderIndex() uint32{
	leaderIndex := 0
	for index, m := range sm.cfg.StoremanNodes {
		leaderIndex = index
		strip := m.IP.String()
		if m.TCP != 0 && strip != "0.0.0.0" {
			break
		}
	}
	return uint32(leaderIndex)
}
// runMessageLoop reads and processes inbound messages directly to merge into client-global state.
func (sm *Storeman) runMessageLoop(p *Peer, rw p2p.MsgReadWriter) error {

	log.SyslogInfo("runMessageLoop begin")
	defer log.SyslogInfo("runMessageLoop exit")

	leaderIndex := sm.getLeaderIndex()
	for {
		// fetch the next packet
		packet, err := rw.ReadMsg()
		if err != nil {
			log.SyslogErr("runMessageLoop", "peer", p.Peer.ID().String(), "err", err.Error())
			return err
		}

		switch packet.Code {

		case mpcprotocol.GetPeersInfo:
			var peerGeting StrmanGetPeers
			err := rlp.Decode(packet.Payload, &peerGeting)
			if err != nil {
				log.SyslogErr("failed decode peers getting info", "err", err.Error())
				return err
			}

			sm.peerMu.Lock()

			sm.peersPort[p.ID()] = peerGeting.LocalPort
			if err != nil {
				log.SyslogErr("failed decode port info", "err", err.Error())
				return err
			}

			log.Debug("adding peer", "", peerGeting.LocalPort)

			allp := &StrmanAllPeers{make([]string, 0), make([]string, 0), make([]string, 0)}

			for _, smpr := range sm.peers {
				if sm.peersPort[smpr.Peer.ID()] == "" ||
					smpr.Peer.ID().String() == sm.cfg.StoremanNodes[leaderIndex].ID.String() {
					continue
				}

				n := smpr.Peer.Info()

				addr, err := net.ResolveTCPAddr("tcp", n.Network.RemoteAddress)
				if err != nil {
					log.SyslogErr("failed get address for peer", "err", err.Error())
					return err
				}

				splits := strings.Split(addr.String(), ":")

				allp.Ip = append(allp.Ip, splits[0])

				allp.Port = append(allp.Port, sm.peersPort[smpr.Peer.ID()])
				allp.Nodeid = append(allp.Nodeid, smpr.ID().String())

				log.Debug("append peer addrs,port", splits[0], sm.peersPort[smpr.ID()])
			}
			sm.peerMu.Unlock()

			if len(allp.Port) > 0 {
				log.Debug("send all peers from leader, count", "", len(allp.Port))
				p.sendAllpeers(allp)
			}

		case mpcprotocol.AllPeersInfo:

			var allp StrmanAllPeers
			err := rlp.Decode(packet.Payload, &allp)
			if err != nil {
				log.SyslogErr("failed decode all peers info", "err", err.Error())
				return err
			}

			for i := 0; i < len(allp.Port); i++ {
				if allp.Nodeid[i] == sm.server.Self().ID.String() ||
					allp.Nodeid[i] == sm.cfg.StoremanNodes[leaderIndex].ID.String() {
					continue
				}

				//if allready exist,check next
				url := "enode://" + allp.Nodeid[i] + "@" + allp.Ip[i] + ":" + allp.Port[i]

				log.Debug("got peer, url=", "", url)

				nd, err := discover.ParseNode(url)
				if err != nil {
					log.SyslogErr("failed parse peer url", "err", err.Error())
					return err
				}

				sm.server.AddPeer(nd)
			}

		default:

			log.SyslogInfo("runMessageLoop, received a msg", "peer", p.Peer.ID().String(), "packet size", packet.Size)
			if packet.Size > sm.MaxMessageSize() {
				log.SyslogWarning("runMessageLoop, oversized message received", "peer", p.Peer.ID().String(), "packet size", packet.Size)
			} else {
				err = sm.mpcDistributor.GetMessage(p.Peer.ID(), rw, &packet)
				if err != nil {
					log.SyslogErr("runMessageLoop, distributor handle msg fail", "err", err.Error())
				}
			}
		}

		packet.Discard()
	}
}

// APIs returns the RPC descriptors the Whisper implementation offers
func (sm *Storeman) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: mpcprotocol.PName,
			Version:   mpcprotocol.PVerStr,
			Service:   &StoremanAPI{sm: sm},
			Public:    true,
		},
	}
}

// Protocols returns the whisper sub-protocols ran by this particular client.
func (sm *Storeman) Protocols() []p2p.Protocol {
	return []p2p.Protocol{sm.protocol}
}

// Start implements node.Service, starting the background data propagation thread
// of the Whisper protocol.
func (sm *Storeman) Start(server *p2p.Server) error {

	sm.mpcDistributor.Self = server.Self()
	sm.mpcDistributor.StoreManGroup = make([]discover.NodeID, len(server.StoremanNodes))
	sm.storemanPeers = make(map[discover.NodeID]bool)
	sm.server = server
	for i, item := range server.StoremanNodes {
		sm.mpcDistributor.StoreManGroup[i] = item.ID
		sm.storemanPeers[item.ID] = true
	}

	sm.mpcDistributor.InitStoreManGroup()

	go sm.checkPeerInfo()

	return nil

}

func (sm *Storeman) checkPeerInfo() {

	// Start the tickers for the updates
	keepQuest := time.NewTicker(mpcprotocol.KeepaliveCycle * time.Second)

	//leaderIndex := 0
	//for index, m := range sm.cfg.StoremanNodes {
	//	leaderIndex = index
	//	strip := m.IP.String()
	//	if m.TCP != 0 && strip != "0.0.0.0" {
	//		break
	//	}
	//}

	leaderIndex := sm.getLeaderIndex()

	//leaderid, err := discover.BytesID(sm.cfg.StoremanNodes[0].ID.Bytes())
	leaderid, err := discover.BytesID(sm.cfg.StoremanNodes[leaderIndex].ID.Bytes())

	if err != nil {
		log.Info("err decode leader node id from config")
	}

	//if sm.cfg.StoremanNodes[0].ID.String() == sm.server.Self().ID.String() {
	//	return
	//}

	if sm.cfg.StoremanNodes[leaderIndex].ID.String() == sm.server.Self().ID.String() {
		return
	}

	//leader will not checkPeerInfo
	log.Info("Entering checkPeerInfo")
	// Loop and transmit until termination is requested
	for {

		select {
		case <-keepQuest.C:
			//log.Info("Entering checkPeerInfo for loop")
			if sm.IsActivePeer(&leaderid) {
				splits := strings.Split(sm.server.ListenAddr, ":")
				sm.SendToPeer(&leaderid, mpcprotocol.GetPeersInfo, StrmanGetPeers{splits[len(splits)-1]})
			} else {
				log.Info("leader is connecting...")
				//sm.server.AddPeer(sm.server.StoremanNodes[0])
				sm.server.AddPeer(sm.server.StoremanNodes[leaderIndex])
			}

		}
	}
}

// Stop implements node.Service, stopping the background data propagation thread
// of the Whisper protocol.
func (sm *Storeman) Stop() error {
	return nil
}

func (sm *Storeman) SendToPeer(peerID *discover.NodeID, msgcode uint64, data interface{}) error {
	sm.peerMu.RLock()
	defer sm.peerMu.RUnlock()
	peer, exist := sm.peers[*peerID]
	if exist {
		return p2p.Send(peer.ws, msgcode, data)
	} else {
		log.SyslogErr("peer not find", "peer", peerID.String())
	}
	return nil
}

func (sm *Storeman) IsActivePeer(peerID *discover.NodeID) bool {
	sm.peerMu.RLock()
	defer sm.peerMu.RUnlock()
	_, exist := sm.peers[*peerID]
	return exist
}

// HandlePeer is called by the underlying P2P layer when the whisper sub-protocol
// connection is negotiated.
func (sm *Storeman) HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {

	if _, exist := sm.storemanPeers[peer.ID()]; !exist {
		return errors.New("Peer is not in storemangroup")
	}

	log.Info("handle new peer", "remoteAddr", peer.RemoteAddr().String(), "peerID", peer.ID().String())

	// Create the new peer and start tracking it
	storemanPeer := newPeer(sm, peer, rw)

	sm.peerMu.Lock()
	sm.peers[storemanPeer.ID()] = storemanPeer
	sm.peerMu.Unlock()

	// Run the peer handshake and state updates
	if err := storemanPeer.handshake(); err != nil {
		log.SyslogErr("storemanPeer.handshake failed", "peerID", peer.ID().String(), "err", err.Error())
		return err
	}

	defer func() {
		sm.peerMu.Lock()

		delete(sm.peers, storemanPeer.ID())

		for _, smnode := range sm.server.StoremanNodes {
			if smnode.ID == storemanPeer.ID() {
				log.Info("remove peer", "pid", smnode.ID)
				sm.server.RemovePeer(smnode)
				break
			}
		}

		sm.peerMu.Unlock()
	}()

	storemanPeer.start()
	defer storemanPeer.stop()

	return sm.runMessageLoop(storemanPeer, rw)
}

////////////////////////////////////
// StoremanAPI
////////////////////////////////////
type StoremanAPI struct {
	sm *Storeman
}

func (sa *StoremanAPI) Version(ctx context.Context) (v string) {
	return mpcprotocol.PVerStr
}

func (sa *StoremanAPI) Peers(ctx context.Context) []*p2p.PeerInfo {
	var ps []*p2p.PeerInfo
	for _, p := range sa.sm.peers {
		ps = append(ps, p.Peer.Info())
	}

	return ps
}

//func (sa *StoremanAPI) CreateGPK(ctx context.Context) (pk hexutil.Bytes, err error) {
//
//	log.SyslogInfo("CreateGPK begin")
//	log.SyslogInfo("CreateGPK begin", "peers", len(sa.sm.peers), "storeman peers", len(sa.sm.storemanPeers))
//
//	if len(sa.sm.storemanPeers)+1 < mpcprotocol.MpcSchnrThr {
//		return []byte{}, mpcprotocol.ErrTooLessStoreman
//	}
//
//	gpk, err := sa.sm.mpcDistributor.CreateRequestGPK()
//	if err == nil {
//		log.SyslogInfo("CreateGPK end", "gpk", hexutil.Encode(gpk))
//	} else {
//		log.SyslogErr("CreateGPK end", "err", err.Error())
//	}
//
//	return gpk, err
//}

//func (sa *StoremanAPI) SignDataByApprove(ctx context.Context, data mpcprotocol.SendData) (result mpcprotocol.SignedResult, err error) {
//	//Todo  check the input parameter
//
//	if len(sa.sm.storemanPeers)+1 < mpcprotocol.MpcSchnrThr {
//		return mpcprotocol.SignedResult{R: []byte{}, S: []byte{}}, mpcprotocol.ErrTooLessStoreman
//	}
//
//	PKBytes := data.PKBytes
//
//	//signed, err := sa.sm.mpcDistributor.CreateReqMpcSign([]byte(data.Data), PKBytes)
//	signed, err := sa.sm.mpcDistributor.CreateReqMpcSign([]byte(data.Data), []byte(data.Extern), PKBytes,1)
//
//	// signed   R // s
//	if err == nil {
//		log.SyslogInfo("SignMpcTransaction end", "signed", common.ToHex(signed))
//	} else {
//		log.SyslogErr("SignMpcTransaction end", "err", err.Error())
//		return mpcprotocol.SignedResult{R: []byte{}, S: []byte{}}, err
//	}
//
//	return mpcprotocol.SignedResult{R: signed[0:65], S: signed[65:]}, nil
//}

//func (sa *StoremanAPI) SignData(ctx context.Context, data mpcprotocol.SendData) (result mpcprotocol.SignedResult, err error) {
//	//Todo  check the input parameter
//
//	if len(sa.sm.storemanPeers)+1 < mpcprotocol.MpcSchnrThr {
//		return mpcprotocol.SignedResult{R: []byte{}, S: []byte{}}, mpcprotocol.ErrTooLessStoreman
//	}
//
//	PKBytes := data.PKBytes
//
//	//signed, err := sa.sm.mpcDistributor.CreateReqMpcSign([]byte(data.Data), PKBytes)
//	signed, err := sa.sm.mpcDistributor.CreateReqMpcSign([]byte(data.Data), []byte(data.Extern), PKBytes,0)
//
//	// signed   R // s
//	if err == nil {
//		log.SyslogInfo("SignMpcTransaction end", "signed", common.ToHex(signed))
//	} else {
//		log.SyslogErr("SignMpcTransaction end", "err", err.Error())
//		return mpcprotocol.SignedResult{R: []byte{}, S: []byte{}}, err
//	}
//
//	return mpcprotocol.SignedResult{R: signed[0:65], S: signed[65:]}, nil
//}

//func (sa *StoremanAPI) AddValidData(ctx context.Context, data mpcprotocol.SendData) error {
//	return validator.AddValidData(&data)
//}
//
//// non leader node polling the data received from leader node
//func (sa *StoremanAPI) GetDataForApprove(ctx context.Context) ([]mpcprotocol.SendData, error) {
//	return validator.GetDataForApprove()
//}
//
////// non leader node ApproveData, and make sure that the data is really required to be signed by them.
//func (sa *StoremanAPI) ApproveData(ctx context.Context, data []mpcprotocol.SendData) []error {
//	return validator.ApproveData(data)
//}

func (sa *StoremanAPI) CreateMpcAccount(ctx context.Context, accType string) (common.Address, error) {
	log.SyslogInfo("CreateMpcAccount begin", "accType", accType)

	if !mpcprotocol.CheckAccountType(accType) {
		return common.Address{}, mpcprotocol.ErrInvalidStmAccType
	}

	if len(sa.sm.peers) < len(sa.sm.storemanPeers)-1 {
		return common.Address{}, mpcprotocol.ErrTooLessStoreman
	}

	if len(sa.sm.storemanPeers) > 22 {
		return common.Address{}, mpcprotocol.ErrTooMoreStoreman
	}

	addr, err := sa.sm.mpcDistributor.CreateRequestStoremanAccount(accType)
	if err == nil {
		log.SyslogInfo("CreateMpcAccount end", "addr", addr.String())
	} else {
		log.SyslogErr("CreateMpcAccount end", "err", err.Error())
	}

	return addr, err
}

func (sa *StoremanAPI) SignMpcTransaction(ctx context.Context, tx mpcprotocol.SendTxArgs) (hexutil.Bytes, error) {
	if tx.To == nil ||
		tx.Gas == nil ||
		tx.GasPrice == nil ||
		tx.Value == nil ||
		tx.Nonce == nil ||
		tx.ChainID == nil {
		return nil, mpcprotocol.ErrInvalidMpcTx
	}

	log.SyslogInfo("@@@@@SignMpcTransaction begin", "@@@@@txInfo", tx.String())

	if len(sa.sm.peers) < mpcprotocol.MPCDegree*2 {
		return nil, mpcprotocol.ErrTooLessStoreman
	}
	sa.sm.mpcDistributor.SetCurPeerCount(uint16(len(sa.sm.peers)))

	trans := types.NewTransaction(uint64(*tx.Nonce), *tx.To, (*big.Int)(tx.Value), (*big.Int)(tx.Gas), (*big.Int)(tx.GasPrice), tx.Data)
	signed, err := sa.sm.mpcDistributor.CreateRequestMpcSign(trans, tx.From, tx.ChainType, tx.SignType, (*big.Int)(tx.ChainID))
	if err == nil {
		log.SyslogInfo("@@@@@@@@@@SignMpcTransaction end", "signed", common.ToHex(signed), "txInfo", tx.String())
	} else {
		log.SyslogErr("@@@@@@@@@@SignMpcTransaction end", "err", err.Error(), "txInfo", tx.String())
	}

	return signed, err
}

func (sa *StoremanAPI) SignMpcBtcTransaction(ctx context.Context, args btc.MsgTxArgs) ([]hexutil.Bytes, error) {
	log.SyslogInfo("@@@@@SignMpcBtcTransaction begin", "@@@@@txInfo", args.String())

	if len(sa.sm.peers) < mpcprotocol.MPCDegree*2 {
		return nil, mpcprotocol.ErrTooLessStoreman
	}
	sa.sm.mpcDistributor.SetCurPeerCount(uint16(len(sa.sm.peers)))

	msgTx, err := btc.GetMsgTxFromMsgTxArgs(&args)
	if err != nil {
		return nil, err
	}

	if len(msgTx.TxIn) == 0 {
		log.SyslogErr("SignMpcBtcTransaction, invalid btc MsgTxArgs, doesn't have TxIn")
		return nil, errors.New("invalid btc MsgTxArgs, doesn't have TxIn")
	}

	signeds, err := sa.sm.mpcDistributor.CreateRequestBtcMpcSign(&args)
	if err != nil {
		log.SyslogErr("@@@@@@@@@@SignMpcBtcTransaction end", "err", err.Error(), "txInfo", args.String())
		return nil, err
	}

	for i := 0; i < len(signeds); i++ {
		log.SyslogInfo("@@@@@@@@@@SignMpcBtcTransaction end", "signed", common.ToHex(signeds[i]), "txInfo", args.String())
	}

	return signeds, err
}

// APIs returns the RPC descriptors the Whisper implementation offers
//AddValidMpcTx stores raw data of cross chain transaction for MPC signing verification
func (sa *StoremanAPI) AddValidMpcTx(ctx context.Context, tx mpcprotocol.SendTxArgs) error {
	return validator.AddValidMpcTx(&tx)
}

func (sa *StoremanAPI) AddValidMpcBtcTx(ctx context.Context, args btc.MsgTxArgs) error {
	log.SyslogInfo("AddValidMpcBtcTx", "txInfo", args.String())
	return validator.AddValidMpcBtcTx(&args)
}
