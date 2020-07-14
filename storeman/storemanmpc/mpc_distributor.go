package storemanmpc

import (
	"crypto/ecdsa"
	"errors"
	"github.com/wanchain/schnorr-mpc/accounts"
	"github.com/wanchain/schnorr-mpc/accounts/keystore"
	"github.com/wanchain/schnorr-mpc/awskms"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	"github.com/wanchain/schnorr-mpc/p2p"
	"github.com/wanchain/schnorr-mpc/p2p/discover"
	"github.com/wanchain/schnorr-mpc/rlp"
	"github.com/wanchain/schnorr-mpc/storeman/osmconf"
	schcomm "github.com/wanchain/schnorr-mpc/storeman/schnorrcomm"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpc"
	"github.com/wanchain/schnorr-mpc/storeman/schnorrmpcbn"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"github.com/wanchain/schnorr-mpc/storeman/validator"
	"io/ioutil"
	"math/big"
	"sync"
)

type MpcContextCreater interface {
	CreateContext(int, uint64, []mpcprotocol.PeerInfo, uint16, uint8, ...MpcValue) (MpcInterface, error) //createContext
}

type MpcValue struct {
	Key       string
	Value     []big.Int
	ByteValue []byte
}

func (v *MpcValue) String() string {
	strRet := "key=" + v.Key
	for i := range v.Value {
		strRet += ", value:" + v.Value[i].String()
	}

	if v.ByteValue != nil {
		strRet += ", value:" + common.ToHex(v.ByteValue)
	}

	return strRet
}

type MpcInterface interface {
	getMessage(*discover.NodeID, *mpcprotocol.MpcMessage, *[]mpcprotocol.PeerInfo) error
	mainMPCProcess(manager mpcprotocol.StoremanManager) error
	getMpcResult(err error) (interface{}, error)
	quit(error)
}

type P2pMessager interface {
	SendToPeer(*discover.NodeID, uint64, interface{}) error
	IsActivePeer(*discover.NodeID) bool
}

type mpcAccount struct {
	address      common.Address
	privateShare big.Int
	peers        []mpcprotocol.PeerInfo
	externString string
}

type KmsInfo struct {
	AKID      string
	SecretKey string
	Region    string
}

type MpcDistributor struct {
	mu             sync.RWMutex
	Self           *discover.Node
	StoreManGroup  []discover.NodeID
	storeManIndex  map[discover.NodeID]byte
	mpcCreater     MpcContextCreater
	mpcMap         map[uint64]MpcInterface
	AccountManager *accounts.Manager
	P2pMessager    P2pMessager
	accMu          sync.Mutex
	mpcAccountMap  map[common.Address]*mpcAccount
	enableAwsKms   bool
	kmsInfo        KmsInfo
	password       string
	peerCount      uint16
}

func CreateMpcDistributor(accountManager *accounts.Manager,
	msger P2pMessager,
	aKID,
	secretKey,
	region,
	password string) *MpcDistributor {

	kmsInfo := KmsInfo{aKID, secretKey, region}
	mpc := &MpcDistributor{
		mu:             sync.RWMutex{},
		mpcCreater:     &MpcCtxFactory{},
		mpcMap:         make(map[uint64]MpcInterface),
		AccountManager: accountManager,
		accMu:          sync.Mutex{},
		mpcAccountMap:  make(map[common.Address]*mpcAccount),
		kmsInfo:        kmsInfo,
		password:       password,
		P2pMessager:    msger,
		peerCount:      uint16(0),
	}

	mpc.enableAwsKms = (aKID != "") && (secretKey != "") && (region != "")

	return mpc
}

func GetPrivateShare(ks *keystore.KeyStore,
	address common.Address,
	enableKms bool,
	kmsInfo *KmsInfo,
	password string) (*keystore.Key, int, error) {

	account := accounts.Account{Address: address}
	account, err := ks.Find(account)
	if err != nil {
		log.SyslogErr("find account from keystore fail", "addr", address.String(), "err", err.Error())
		return nil, 0x00, err
	}

	var keyjson []byte
	if enableKms {
		keyjson, err = awskms.DecryptFileToBuffer(account.URL.Path, kmsInfo.AKID, kmsInfo.SecretKey, kmsInfo.Region)
	} else {
		keyjson, err = ioutil.ReadFile(account.URL.Path)
	}

	if err != nil {
		log.SyslogErr("get account keyjson fail",
			"addr", address.String(),
			"path", account.URL.Path,
			"err", err.Error())

		return nil, 0x01, err
	}

	key, err := keystore.DecryptKey(keyjson, password)
	if err != nil {
		log.SyslogErr("decrypt account keyjson fail",
			"addr", address.String(),
			"path", account.URL.Path,
			"err", err.Error())

		return nil, 0x011, err
	}

	return key, 0x111, nil
}

func (mpcServer *MpcDistributor) GetMessage(PeerID discover.NodeID, rw p2p.MsgReadWriter, msg *p2p.Msg) error {
	log.SyslogInfo("MpcDistributor GetMessage begin", "msgCode", msg.Code)

	switch msg.Code {

	case mpcprotocol.StatusCode:
		// this should not happen, but no need to panic; just ignore this message.
		log.SyslogInfo("status message received", "peer", PeerID.String())

	case mpcprotocol.KeepaliveCode:
		// this should not happen, but no need to panic; just ignore this message.

	case mpcprotocol.KeepaliveOkCode:
		// this should not happen, but no need to panic; just ignore this message.

	case mpcprotocol.MPCError:
		var mpcMessage mpcprotocol.MpcMessage
		err := rlp.Decode(msg.Payload, &mpcMessage)
		if err != nil {
			log.SyslogErr("MpcDistributor.GetMessage, rlp decode MPCError msg fail", "err", err.Error())
			return err
		}

		errText := string(mpcMessage.Peers[:])
		log.SyslogErr("MpcDistributor.GetMessage, MPCError message received", "peer", PeerID.String(), "err", errText)
		go mpcServer.QuitMpcContext(&mpcMessage)

	case mpcprotocol.RequestMPC:
		log.SyslogInfo("MpcDistributor.GetMessage, RequestMPC message received", "peer", PeerID.String())
		var mpcMessage mpcprotocol.MpcMessage
		err := rlp.Decode(msg.Payload, &mpcMessage)
		if err != nil {
			log.SyslogErr("MpcDistributor.GetMessage, rlp decode RequestMPC msg fail", "err", err.Error())
			return err
		}

		//create context
		go func() {
			err := mpcServer.createMpcCtx(&mpcMessage)

			if err != nil {
				log.SyslogErr("createMpcContext fail", "err", err.Error())
			}
		}()

	case mpcprotocol.MPCMessage:
		var mpcMessage mpcprotocol.MpcMessage
		err := rlp.Decode(msg.Payload, &mpcMessage)
		if err != nil {
			log.SyslogErr("GetP2pMessage fail", "err", err.Error())
			return err
		}

		//log.SyslogInfo("MpcDistributor.GetMessage, MPCMessage message received", "peer", PeerID.String())
		go mpcServer.getMpcMessage(&PeerID, &mpcMessage)

	default:
		// New message types might be implemented in the future versions of Whisper.
		// For forward compatibility, just ignore.
	}

	return nil
}

func (mpcServer *MpcDistributor) CreateRequestGPK() (interface{}, error) {
	log.SyslogInfo("CreateRequestGPK begin")

	preSetValue := make([]MpcValue, 0, 1)
	value, err := mpcServer.createRequestMpcContext(mpcprotocol.MpcGPKLeader,
		preSetValue...)

	if err != nil {
		return []byte{}, err
	} else {
		return value, err
	}
}

func (mpcServer *MpcDistributor) CurPeerCount() uint16 {
	return mpcServer.peerCount
}
func (mpcServer *MpcDistributor) SetCurPeerCount(peerCount uint16) {
	mpcServer.peerCount = peerCount
}

func (mpcServer *MpcDistributor) CreateReqMpcSign(data []byte, extern []byte, pkBytes []byte, byApprove int64, curveBytes []byte) (interface{}, error) {

	log.SyslogInfo("CreateReqMpcSign begin")
	grpId, _ := osmconf.GetOsmConf().GetGrpInxByGpk(pkBytes)

	// MpcGpkBytes stores the gpk bytes.
	grpIdBytes, _ := hexutil.Decode(grpId)
	value, err := mpcServer.createRequestMpcContext(mpcprotocol.MpcSignLeader,
		MpcValue{mpcprotocol.MpcGrpId, nil, grpIdBytes},
		MpcValue{mpcprotocol.MpcGpkBytes, nil, pkBytes[:]},
		MpcValue{mpcprotocol.PublicKeyResult, nil, pkBytes[:]},
		MpcValue{mpcprotocol.MpcM, nil, data},
		MpcValue{mpcprotocol.MpcExt, nil, extern},
		MpcValue{mpcprotocol.MpcByApprove, []big.Int{*(big.NewInt(byApprove))}, nil},
		MpcValue{mpcprotocol.MpcCurve, nil, curveBytes[:]})

	return value, err
}

func (mpcServer *MpcDistributor) createRequestMpcContext(ctxType int, preSetValue ...MpcValue) (interface{}, error) {
	log.SyslogInfo("MpcDistributor createRequestMpcContext begin")
	mpcID, err := mpcServer.getMpcID()
	if err != nil {
		return nil, err
	}

	peers := []mpcprotocol.PeerInfo{}

	var grpIdStr string
	for _, item := range preSetValue {
		if item.Key == mpcprotocol.MpcGrpId {
			grpIdStr = hexutil.Encode(item.ByteValue)
			break
		}
	}

	var curveType uint8
	for _, item := range preSetValue {
		if item.Key == mpcprotocol.MpcCurve {
			curveBig := big.NewInt(0).SetBytes(item.ByteValue)
			curveType = uint8(curveBig.Uint64())
			break
		}
	}

	var smpc mpcprotocol.SchnorrMPCer
	switch int(curveType) {
	case mpcprotocol.SK256Curve:
		smpc = schnorrmpc.NewSkSchnorrMpc()
	case mpcprotocol.BN256Curve:
		smpc = schnorrmpcbn.NewBnSchnorrMpc()
	default:
		smpc = schnorrmpc.NewSkSchnorrMpc()
	}

	var address common.Address
	var gpkString string
	if ctxType == mpcprotocol.MpcSignLeader {
		for _, item := range preSetValue {
			if item.Key == mpcprotocol.MpcGpkBytes {
				//todo for bn256
				pt, err := smpc.UnMarshPt(item.ByteValue)
				if err != nil {
					if !schcomm.PocTest {
						return []byte{}, err
					}
				}
				//address, err = schnorrmpc.PkToAddress(item.ByteValue)
				address, err = smpc.PtToAddress(pt)
				if err != nil {
					if !schcomm.PocTest {
						return []byte{}, err
					}
				}
				gpkString = hexutil.Encode(item.ByteValue)
				break
			}
		}

		if schcomm.PocTest {
			b, _ := osmconf.GetOsmConf().GetPrivateShare(curveType)

			value := &MpcValue{mpcprotocol.MpcPrivateShare, []big.Int{b}, nil}
			// mpc private share
			preSetValue = append(preSetValue, *value)
		} else {
			value, err := mpcServer.loadStoremanAddress(curveType, gpkString, &address)
			if err != nil {

				log.SyslogErr("MpcDistributor createRequestMpcContext, loadStoremanAddress fail",
					"address", address.String(),
					"err", err.Error())

				return []byte{}, err
			}

			// mpc private share
			preSetValue = append(preSetValue, *value)
		}
	}

	peers, err = osmconf.GetOsmConf().GetPeersByGrpId(grpIdStr)
	if err != nil {
		log.SyslogErr("createRequestMpcContext", "GetPeersByGrpId", err.Error())
		return nil, err
	}
	mpc, err := mpcServer.mpcCreater.CreateContext(ctxType,
		mpcID,
		peers,
		mpcServer.peerCount,
		curveType,
		preSetValue...)
	if err != nil {
		log.SyslogErr("MpcDistributor createRequestMpcContext, CreateContext fail", "err", err.Error())
		return []byte{}, err
	}

	log.SyslogInfo("MpcDistributor createRequestMpcContext", "ctxType", ctxType, "mpcID", mpcID)

	mpcServer.addMpcContext(mpcID, mpc)
	defer mpcServer.removeMpcContext(mpcID)
	err = mpc.mainMPCProcess(mpcServer)
	return mpc.getMpcResult(err)
}

func (mpcServer *MpcDistributor) loadStoremanAddress(curveType uint8, gpkStr string, address *common.Address) (*MpcValue, error) {
	log.SyslogInfo("MpcDistributor.loadStoremanAddress begin", "address", address.String())

	mpcServer.accMu.Lock()
	defer mpcServer.accMu.Unlock()
	value, exist := mpcServer.mpcAccountMap[*address]
	password, _ := osmconf.GetOsmConf().GetGpkPwd(gpkStr)
	var key *keystore.Key
	var err error
	if !exist {
		ks := mpcServer.AccountManager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
		key, _, err = GetPrivateShare(ks, *address, mpcServer.enableAwsKms, &mpcServer.kmsInfo, password)
		if err != nil {
			return nil, err
		}

		value = &mpcAccount{*address, *key.PrivateKey.D, nil, key.Exten}

		mpcServer.mpcAccountMap[*address] = value
	}

	var smpcer mpcprotocol.SchnorrMPCer
	switch int(curveType) {
	case mpcprotocol.SK256Curve:
		smpcer = schnorrmpc.NewSkSchnorrMpc()
	case mpcprotocol.BN256Curve:
		smpcer = schnorrmpcbn.NewBnSchnorrMpc()
	default:
		smpcer = schnorrmpc.NewSkSchnorrMpc()
	}
	gpkShare, _ := smpcer.SkG(&value.privateShare)
	log.SyslogInfo("loadStoremanAddress", "gpkShare", smpcer.PtToHexString(gpkShare))

	return &MpcValue{mpcprotocol.MpcPrivateShare, []big.Int{value.privateShare}, nil}, nil
}

func (mpcServer *MpcDistributor) getMpcID() (uint64, error) {
	var mpcID uint64
	var err error
	for {
		mpcID, err = schcomm.UintRand(uint64(1<<64 - 1))
		if err != nil {
			log.SyslogErr("MpcDistributor getMpcID, UnitRand fail", "err", err.Error())
			return 0, err
		}

		mpcServer.mu.RLock()
		_, exist := mpcServer.mpcMap[mpcID]
		mpcServer.mu.RUnlock()
		if !exist {
			return mpcID, nil
		}
	}
}

func (mpcServer *MpcDistributor) QuitMpcContext(msg *mpcprotocol.MpcMessage) {
	mpcServer.mu.RLock()
	mpc, exist := mpcServer.mpcMap[msg.ContextID]
	mpcServer.mu.RUnlock()
	if exist {
		mpc.quit(errors.New(string(msg.Peers[:])))
	}
}

func (mpcServer *MpcDistributor) createMpcCtx(mpcMessage *mpcprotocol.MpcMessage, preSetValue ...MpcValue) error {
	log.SyslogInfo("MpcDistributor createMpcCtx begin")

	mpcServer.mu.RLock()
	_, exist := mpcServer.mpcMap[mpcMessage.ContextID]
	mpcServer.mu.RUnlock()
	if exist {
		log.SyslogErr("createMpcCtx fail", "err", mpcprotocol.ErrMpcContextExist.Error())
		return mpcprotocol.ErrMpcContextExist
	}

	var ctxType int
	nType := mpcMessage.Data[0].Int64()
	nByApprove := mpcMessage.Data[1].Int64()
	curPeerCount := uint16(mpcMessage.Data[2].Int64())

	if nType == mpcprotocol.MpcGPKLeader {
		ctxType = mpcprotocol.MpcGPKPeer
	} else {
		ctxType = mpcprotocol.MpcSignPeer
	}

	log.SyslogInfo("createMpcCtx", "ctxType", ctxType, "ctxId", mpcMessage.ContextID)
	var grpId string
	var gpkStr string
	var curveType uint8
	if ctxType == mpcprotocol.MpcSignPeer {
		log.SyslogInfo("createMpcCtx MpcSignPeer")
		mpcM := mpcMessage.BytesData[0]
		address := mpcMessage.BytesData[1]
		mpcExt := mpcMessage.BytesData[2]
		curveTypeBytes := mpcMessage.BytesData[3]
		curveType = uint8(big.NewInt(0).SetBytes(curveTypeBytes).Uint64())
		//add := common.Address{}
		//copy(add[:], address)

		var smpc mpcprotocol.SchnorrMPCer
		switch int(curveType) {
		case mpcprotocol.SK256Curve:
			smpc = schnorrmpc.NewSkSchnorrMpc()
		case mpcprotocol.BN256Curve:
			smpc = schnorrmpcbn.NewBnSchnorrMpc()
		default:
			smpc = schnorrmpc.NewSkSchnorrMpc()
		}

		pt, err := smpc.UnMarshPt(address[:])
		if err != nil {
			if !schcomm.PocTest {
				return err
			}
		}

		add, err := smpc.PtToAddress(pt)
		if err != nil {
			if !schcomm.PocTest {
				return err
			}
		}

		gpkStr = hexutil.Encode(address[:])

		log.SyslogInfo("createMpcCtx", "address", address, "mpcM", mpcM)

		var MpcPrivateShare *MpcValue

		if schcomm.PocTest {
			b, _ := osmconf.GetOsmConf().GetPrivateShare(curveType)
			MpcPrivateShare = &MpcValue{mpcprotocol.MpcPrivateShare, []big.Int{b}, nil}
			// mpc private share
		} else {
			// load account
			MpcPrivateShare, err = mpcServer.loadStoremanAddress(curveType, gpkStr, &add)
			if err != nil {
				return err
			}
		}

		grpId, _ = osmconf.GetOsmConf().GetGrpInxByGpk(address[:])
		grpIdBytes, _ := hexutil.Decode(grpId)
		preSetValue = append(preSetValue, MpcValue{mpcprotocol.MpcGrpId, nil, grpIdBytes})
		preSetValue = append(preSetValue, MpcValue{mpcprotocol.MpcGpkBytes, nil, address})
		preSetValue = append(preSetValue, MpcValue{mpcprotocol.MpcM, nil, mpcM})
		preSetValue = append(preSetValue, MpcValue{mpcprotocol.MpcExt, nil, mpcExt})
		preSetValue = append(preSetValue, MpcValue{mpcprotocol.MpcCurve, nil, curveTypeBytes})
		preSetValue = append(preSetValue, *MpcPrivateShare)

		receivedData := &mpcprotocol.SendData{PKBytes: address, Data: mpcM[:], Curve: curveTypeBytes, Extern: string(mpcExt[:])}

		if nByApprove != 0 {
			addApprovingResult := validator.AddApprovingData(receivedData)
			if addApprovingResult != nil {
				mpcMsg := &mpcprotocol.MpcMessage{ContextID: mpcMessage.ContextID,
					StepID: 0,
					Peers:  []byte(mpcprotocol.ErrFailedAddApproving.Error())}
				peerInfo, err := osmconf.GetOsmConf().GetPeersByGrpId(grpId)
				if err != nil {
					log.SyslogErr("createMpcCtx", "GetPeersByGrpId", err.Error())
					return err
				}
				peerIDs := make([]discover.NodeID, 0)
				for _, item := range peerInfo {
					peerIDs = append(peerIDs, item.PeerID)
				}

				mpcServer.P2pMessage(&mpcServer.Self.ID, mpcprotocol.MPCError, mpcMsg)

				log.SyslogErr("createMpcContext, AddApprovingData  fail",
					"ContextID", mpcMessage.ContextID, "err", addApprovingResult.Error())
				return mpcprotocol.ErrFailedAddApproving
			}
		}

		verifyResult, err := validator.ValidateData(receivedData)

		if !verifyResult {
			mpcMsg := &mpcprotocol.MpcMessage{ContextID: mpcMessage.ContextID,
				StepID: 0,
				Peers:  []byte(err.Error())}
			peerInfo, err := osmconf.GetOsmConf().GetPeersByGrpId(grpId)
			if err != nil {
				log.SyslogErr("createMpcContext", "GetPeersByGrpId", err.Error())
				return err
			}
			peerIDs := make([]discover.NodeID, 0)
			for _, item := range peerInfo {
				peerIDs = append(peerIDs, item.PeerID)
			}

			mpcServer.P2pMessage(&mpcServer.Self.ID, mpcprotocol.MPCError, mpcMsg)
			log.SyslogErr("createMpcContext, verify data fail", "ContextID", mpcMessage.ContextID)
			return err
		}

	} else if ctxType == mpcprotocol.MpcGPKPeer {
		log.SyslogInfo("createMpcCtx", "ctxType", ctxType)
	}

	msgPeers, err := osmconf.GetOsmConf().GetPeersByGrpId(grpId)
	if err != nil {
		log.SyslogErr("createMpcContext, createContext fail", "err", err.Error())
		return err
	}

	mpc, err := mpcServer.mpcCreater.CreateContext(ctxType,
		mpcMessage.ContextID,
		msgPeers,
		curPeerCount,
		uint8(curveType),
		preSetValue...)

	if err != nil {
		log.SyslogErr("createMpcContext, createContext fail", "err", err.Error())
		return err
	}

	go func() {
		mpcServer.addMpcContext(mpcMessage.ContextID, mpc)
		defer mpcServer.removeMpcContext(mpcMessage.ContextID)
		err = mpc.mainMPCProcess(mpcServer)
	}()

	return nil
}

func (mpcServer *MpcDistributor) addMpcContext(mpcID uint64, mpc MpcInterface) {
	log.SyslogInfo("addMpcContext", "ctxId", mpcID)

	mpcServer.mu.Lock()
	defer mpcServer.mu.Unlock()
	mpcServer.mpcMap[mpcID] = mpc
}

func (mpcServer *MpcDistributor) removeMpcContext(mpcID uint64) {
	log.SyslogInfo("removeMpcContext", "ctxId", mpcID)

	mpcServer.mu.Lock()
	defer mpcServer.mu.Unlock()
	delete(mpcServer.mpcMap, mpcID)
}

func (mpcServer *MpcDistributor) getMpcMessage(PeerID *discover.NodeID, mpcMessage *mpcprotocol.MpcMessage) error {
	log.SyslogInfo("......getMpcMessage",
		"peerid", PeerID.String(),
		"ctxId", mpcMessage.ContextID,
		"stepID", mpcMessage.StepID)

	mpcServer.mu.RLock()
	mpc, exist := mpcServer.mpcMap[mpcMessage.ContextID]
	mpcServer.mu.RUnlock()
	if exist {
		return mpc.getMessage(PeerID, mpcMessage, nil)
	}

	return nil
}

func (mpcServer *MpcDistributor) getOwnerP2pMessage(PeerID *discover.NodeID, code uint64, msg interface{}) error {
	log.SyslogInfo("......Entering MpcDistributor.getOwnerP2pMessage", "peerId", PeerID.String())
	switch code {
	case mpcprotocol.MPCMessage:
		mpcMessage := msg.(*mpcprotocol.MpcMessage)
		mpcServer.getMpcMessage(PeerID, mpcMessage)
	case mpcprotocol.RequestMPCNonce:
		// do nothing
	default:
		return nil
	}

	return nil
}

func (mpcServer *MpcDistributor) SelfNodeId() *discover.NodeID {
	return &mpcServer.Self.ID
}

func (mpcServer *MpcDistributor) P2pMessage(peerID *discover.NodeID, code uint64, msg interface{}) error {
	if *peerID == mpcServer.Self.ID {
		mpcServer.getOwnerP2pMessage(&mpcServer.Self.ID, code, msg)
	} else {
		err := mpcServer.P2pMessager.SendToPeer(peerID, code, msg)
		if err != nil {
			log.SyslogErr("BroadcastMessage fail", "err", err.Error())
		}
	}

	return nil
}

func (mpcServer *MpcDistributor) BroadcastMessage(peers []discover.NodeID, code uint64, msg interface{}) error {
	// peers get from mpc context, and mpc context has build peersInfo by groupID.
	if peers == nil {
		log.Info("Entering BroadcastMessage using mpcServer.StoreManGroup")
		for _, peer := range mpcServer.StoreManGroup {
			if peer == mpcServer.Self.ID {
				mpcServer.getOwnerP2pMessage(&mpcServer.Self.ID, code, msg)
			} else {
				err := mpcServer.P2pMessager.SendToPeer(&peer, code, msg)
				if err != nil {
					log.SyslogErr("BroadcastMessage fail", "peer", peer.String(), "err", err.Error())
				}
			}
		}
	} else {
		log.Info("Entering BroadcastMessage using peers")
		for _, peerID := range peers {
			if peerID == mpcServer.Self.ID {
				mpcServer.getOwnerP2pMessage(&mpcServer.Self.ID, code, msg)
			} else {
				err := mpcServer.P2pMessager.SendToPeer(&peerID, code, msg)
				if err != nil {
					log.SyslogErr("BroadcastMessage fail", "peer", peerID.String(), "err", err.Error())
				}
			}
		}
	}

	return nil
}

func (mpcServer *MpcDistributor) newStoremanKeyStore(pKey *ecdsa.PublicKey,
	pShare *big.Int,
	seeds []uint64,
	passphrase string,
	accType string) (accounts.Account, error) {

	ks := mpcServer.AccountManager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	account, err := ks.NewStoremanAccount(pKey, pShare, seeds, passphrase, accType)
	if err != nil {
		log.SyslogErr("NewStoremanKeyStore fail", "err", err.Error())
	} else {
		log.SyslogInfo("newStoremanKeyStore success", "addr", account.Address.String())
	}

	return account, err
}

func (mpcServer *MpcDistributor) CreateKeystore(result mpcprotocol.MpcResultInterface,
	peers *[]mpcprotocol.PeerInfo,
	accType string) error {

	log.SyslogInfo("MpcDistributor.CreateKeystore begin")
	point, err := result.GetValue(mpcprotocol.PublicKeyResult)
	if err != nil {
		log.SyslogErr("CreateKeystore fail. get PublicKeyResult fail")
		return err
	}

	private, err := result.GetValue(mpcprotocol.MpcPrivateShare)
	if err != nil {
		log.SyslogErr("CreateKeystore fail. get MpcPrivateShare fail")
		return err
	}

	result1 := new(ecdsa.PublicKey)
	result1.Curve = crypto.S256()
	result1.X = big.NewInt(0).SetBytes(point[0].Bytes())
	result1.Y = big.NewInt(0).SetBytes(point[1].Bytes())
	seed := make([]uint64, len(*peers))

	for i, item := range *peers {
		seed[i] = item.Seed
	}

	_, err = mpcServer.newStoremanKeyStore(result1, &private[0], seed, mpcServer.password, accType)
	if err != nil {
		return err
	}

	result.SetByteValue(mpcprotocol.MpcContextResult, crypto.FromECDSAPub(result1))
	log.Info("CreateKeystore ",
		"gpk address", crypto.PubkeyToAddress(*result1),
		"gpk hexutil.Encode", hexutil.Encode(crypto.FromECDSAPub(result1)))

	return nil
}
