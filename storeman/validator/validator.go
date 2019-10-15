package validator

import (
	"bytes"
	"encoding/json"
	"errors"
	lvdberror "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/wanchain/schnorr-mpc/common"
	"github.com/wanchain/schnorr-mpc/common/hexutil"
	"github.com/wanchain/schnorr-mpc/crypto"
	"github.com/wanchain/schnorr-mpc/log"
	mpcprotocol "github.com/wanchain/schnorr-mpc/storeman/storemanmpc/protocol"
	"time"
)

var noticeFuncIds [][4]byte

func init() {

}

// TODO add ValidateData
func ValidateData(data *mpcprotocol.SendData) bool {

	log.SyslogInfo("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&Jacob ValidateData, begin",
		"pk", hexutil.Encode(data.PKBytes),
		"data", hexutil.Encode([]byte(data.Data)))

	sdb, err := GetDB()
	if err != nil {
		log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
		return false
	}

	approvedKey := buildKeyFromData(data, mpcprotocol.MpcApproved)
	_, err = waitKeyFromDB([][]byte{approvedKey})
	if err != nil {
		log.SyslogErr("ValidateData, waitKeyFromDB has fail", "err", err.Error())
		return false
	}

	value, err := sdb.Get(approvedKey)
	if err != nil {
		log.SyslogErr("ValidateData, sdb.Get has fail", "err", err.Error())
		return false
	}

	//var byteDb []byte
	//err = json.Unmarshal(value, &byteDb)
	//if err != nil {
	//	log.SyslogErr("ValidateData, json.Unmarshal has fail", "err", err.Error())
	//	return false
	//}

	var byteRev []byte
	byteRev, err = json.Marshal(&data)
	if err != nil {
		log.SyslogErr("ValidateData, check has fail", "err", err.Error())
		return false
	}

	if !bytes.Equal(value, byteRev) {
		return false
	}

	return true

}

func AddApprovedData(data *mpcprotocol.SendData) error {
	return addApprovedData(data)
}

func AddApprovingData(data *mpcprotocol.SendData) error {
	return addApprovingData(data)
}

func GetDataForApprove() ([]mpcprotocol.SendData, error) {
	log.SyslogInfo("GetDataForApprove, begin")
	sdb, err := GetDB()
	if err != nil {
		log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
		return nil, err
	}

	log.SyslogInfo("GetDataForApprove", "key", mpcprotocol.MpcApprovingKeys)
	ret, err := sdb.Get([]byte(mpcprotocol.MpcApprovingKeys))
	if err != nil {
		log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
		return nil, err
	}
	var approvingKeys [][]byte
	err = json.Unmarshal(ret, &approvingKeys)
	if err != nil {
		return nil, err
	}

	var approvingData []mpcprotocol.SendData
	for i := 0; i < len(approvingKeys); i++ {
		approvingItem, err := sdb.Get(approvingKeys[i])
		if err != nil {
			log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
			return nil, err
		}

		var approvingTemp mpcprotocol.SendData
		err = json.Unmarshal(approvingItem, &approvingTemp)
		if err != nil {
			return nil, err
		}
		approvingData = append(approvingData, approvingTemp)
	}
	log.SyslogInfo("GetDataForApprove succeed to get data from level db after putting key-val pair", "ret", string(ret))
	return approvingData, nil
}

func ApproveData(approveData []mpcprotocol.SendData) []error {
	retResult := make([]error, len(approveData))
	for i := 0; i < len(approveData); i++ {
		dataItem := approveData[i]
		approvingKey := buildKeyFromData(&dataItem, mpcprotocol.MpcApproving)

		// check in approving keys
		sdb, err := GetDB()
		if err != nil {
			log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
			retResult[i] = err
			continue
		}

		ret, err := sdb.Get([]byte(mpcprotocol.MpcApprovingKeys))
		if err != nil {
			log.SyslogErr("GetDataForApprove, getting storeman database fail", "err", err.Error())
			retResult[i] = err
			continue
		}
		var approvingKeys [][]byte
		err = json.Unmarshal(ret, &approvingKeys)
		if err != nil {
			retResult[i] = err
			continue
		}

		if !inByteArray(&approvingKey, &approvingKeys) {
			retResult[i] = errors.New("can not fond in approving keys")
			continue
		}

		// check in approving db
		exist, err := sdb.Has(approvingKey)
		if !exist {
			retResult[i] = errors.New("can not fond in approving db")
			continue
		}
		if err != nil {
			retResult[i] = err
			continue
		}

		// put in approved db
		err = addApprovedData(&dataItem)
		if err != nil {
			retResult[i] = err
			continue
		}

		// delete key in keys
		newApprovingKeys := deleteInByteArray(&approvingKey, &approvingKeys)
		newApprovingKeysBytes, err := json.Marshal(&newApprovingKeys)
		if err != nil {
			retResult[i] = err
			continue
		}
		err = addKeyValueToDB([]byte(mpcprotocol.MpcApprovingKeys), newApprovingKeysBytes)
		if err != nil {
			retResult[i] = err
			continue
		}

		// delete in approving db
		err = sdb.Delete(approvingKey)
		if err != nil {
			retResult[i] = err
			continue
		}
	}

	return retResult
}

func inByteArray(data *[]byte, collection *[][]byte) bool {
	if data == nil || len(*collection) == 0 {
		return false
	}

	for _, value := range *collection {
		if bytes.Compare(*data, value) == 0 {
			return true
		}
	}
	return false
}

func deleteInByteArray(data *[]byte, collection *[][]byte) [][]byte {
	if !inByteArray(data, collection) {
		return *collection
	}

	ret := make([][]byte, 0)
	for _, value := range *collection {
		if bytes.Compare(*data, value) != 0 {
			ret = append(ret, value)
		}
	}
	return ret
}

func waitKeyFromDB(keys [][]byte) ([]byte, error) {
	log.SyslogInfo("waitKeyFromDB, begin")

	for i, key := range keys {
		log.SyslogInfo("waitKeyFromDB", "i", i, "key", hexutil.Encode(key))
	}

	db, err := GetDB()
	if err != nil {
		log.SyslogErr("waitKeyFromDB get database fail", "err", err.Error())
		return nil, err
	}

	start := time.Now()
	for {
		for _, key := range keys {
			isExist, err := db.Has(key)
			if err != nil {
				log.SyslogErr("=================Jacob waitKeyFromDB fail", "err", err.Error())
				return nil, err
			} else if isExist {
				log.SyslogInfo("=================Jacob waitKeyFromDB, got it", "key", common.ToHex(key))
				return key, nil
			}

		}

		if time.Now().Sub(start) >= mpcprotocol.MPCTimeOut {
			log.SyslogInfo("waitKeyFromDB, time out")
			return nil, errors.New("waitKeyFromDB, time out")
		}

		time.Sleep(200 * time.Microsecond)
	}

	return nil, errors.New("waitKeyFromDB, unknown error")
}

func addKeyValueToDB(key, value []byte) error {
	log.SyslogInfo("addKeyValueToDB, begin", "key:", common.ToHex(key))
	sdb, err := GetDB()
	if err != nil {
		log.SyslogErr("addKeyValueToDB, getting storeman database fail", "err", err.Error())
		return err
	}

	err = sdb.Put(key, value)
	if err != nil {
		log.SyslogErr("addKeyValueToDB, getting storeman database fail", "err", err.Error())
		return err
	}

	log.SyslogInfo("addKeyValueToDB", "key", common.ToHex(key))
	ret, err := sdb.Get(key)
	if err != nil {
		log.SyslogErr("addKeyValueToDB, getting storeman database fail", "err", err.Error())
		return err
	}

	log.SyslogInfo("addKeyValueToDB succeed to get data from level db after putting key-val pair", "ret", string(ret))
	return nil
}

// status: approving || approved
func buildKeyFromData(data *mpcprotocol.SendData, status string) []byte {
	// data || status

	// build the key.
	var buffer bytes.Buffer
	buffer.Write(data.PKBytes[:])
	buffer.Write([]byte(data.Data[:]))
	buffer.Write([]byte(status))

	return crypto.Keccak256(buffer.Bytes())
}

func addApprovingData(dataItem *mpcprotocol.SendData) error {

	approvingKey := buildKeyFromData(dataItem, mpcprotocol.MpcApproving)
	// check in approving keys
	sdb, err := GetDB()
	if err != nil {
		log.SyslogErr("addApprovingData, getting storeman database fail", "err", err.Error())
		return err
	}

	ret, err := sdb.Get([]byte(mpcprotocol.MpcApprovingKeys))
	if err != nil && err != lvdberror.ErrNotFound {
		log.SyslogErr("addApprovingData,  sdb.Get fail", "err", err.Error())
		return err
	}
	var approvingKeys [][]byte
	if len(ret) != 0 {
		err = json.Unmarshal(ret, &approvingKeys)
		if err != nil {
			log.SyslogErr("addApprovingData,  Unmarshal fail", "err", err.Error())
			return err
		}
	}

	if inByteArray(&approvingKey, &approvingKeys) {
		return errors.New("already has approving key")
	}

	// check in approving db
	exist, err := sdb.Has(approvingKey)
	if exist {
		return errors.New("already has in approving db")
	}
	if err != nil {
		log.SyslogErr("addApprovingData, sdb.Has fail", "err", err.Error())
		return err
	}

	// put in approving db
	value, err := json.Marshal(&dataItem)
	if err != nil {
		log.SyslogErr("addApprovingData, json.Marshal fail", "err", err.Error())
		return err
	}
	err = addKeyValueToDB(approvingKey, value)
	log.SyslogInfo("===============Jacob addApprovingData ", "approvingKey", hexutil.Encode(approvingKey), "value", value)
	if err != nil {
		log.SyslogErr("addApprovingData, addKeyValueToDB fail", "err", err.Error())
		return err
	}

	// append key in keys
	approvingKeys = append(approvingKeys, approvingKey)

	approvingKeysBytes, err := json.Marshal(&approvingKeys)
	if err != nil {
		log.SyslogErr("addApprovingData, Marshal approvingKeys fail", "err", err.Error())
		return err
	}

	log.SyslogInfo("===============Jacob addApprovingData ",
		"approvingKeys", hexutil.Encode([]byte(mpcprotocol.MpcApprovingKeys)),
		"value", approvingKeysBytes)

	err = addKeyValueToDB([]byte(mpcprotocol.MpcApprovingKeys), approvingKeysBytes)
	if err != nil {
		log.SyslogErr("addApprovingData,  MpcApprovingKeys addKeyValueToDB fail", "err", err.Error())
		return err
	}
	return nil
}

func addApprovedData(data *mpcprotocol.SendData) error {
	log.SyslogInfo("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&Jacob addApprovedData, begin",
		"pk", hexutil.Encode(data.PKBytes),
		"data", hexutil.Encode([]byte(data.Data)))

	val, err := json.Marshal(&data)
	if err != nil {
		log.SyslogErr("addApprovedData, marshal fail", "err", err.Error())
		return err
	}

	key := buildKeyFromData(data, mpcprotocol.MpcApproved)
	log.SyslogInfo("===============Jacob addApprovedData", "data", data.String(), "approved key", hexutil.Encode(key))
	return addKeyValueToDB(key, val)
}

//TODO need delete the approved data when signature complete successfully.
