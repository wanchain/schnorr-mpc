package validator

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/log"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"math/big"
	"strconv"
)

func IsMalice(grpId string, smInx uint16) (bool, error) {

	mc, err := maliceCount(grpId, smInx)
	if err != nil {
		return false, err
	}

	if mc >= uint8(mpcprotocol.MaxMalice) {
		return true, nil
	}
	return false, nil
}

func BuildKey(grpId string, smInx uint16) common.Hash {
	var buf bytes.Buffer
	buf.WriteString(grpId)
	buf.WriteString(strconv.Itoa(int(smInx)))
	return sha256.Sum256(buf.Bytes())
}

func maliceCount(grpId string, smInx uint16) (uint8, error) {
	sdb, err := GetDB()
	if err != nil {
		log.SyslogErr("MaliceCount, getting storeman database fail", "err", err.Error())
		return 0, mpcprotocol.ErrGetDb
	}

	key := BuildKey(grpId, smInx)
	value, err := sdb.Get(key[:])
	if err != nil {
		log.SyslogErr("ValidateData, sdb.Get has fail", "err", err.Error())
		return 0, errors.New("get MaliceCount error")
	}

	return uint8(big.NewInt(0).SetBytes(value).Uint64()), nil
}

func SetMaliceCount(grpId string, smInx uint16, maliceCount uint8) error {
	sdb, err := GetDB()
	if err != nil {
		log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
		return mpcprotocol.ErrGetDb
	}

	key := BuildKey(grpId, smInx)
	value := big.NewInt(0).SetUint64(uint64(maliceCount))

	return sdb.Put(key[:], value.Bytes())
}

func IncMaliceCount(grpId string, smInx uint16) error {
	mc, err := maliceCount(grpId, smInx)
	if err != nil {
		return err
	}
	mc += 1

	return SetMaliceCount(grpId, smInx, mc)
}

func GetMalicIndex(bsender bool, sndInx, rcvIndx uint16) uint16 {
	if bsender {
		return sndInx
	} else {
		return rcvIndx
	}
}
