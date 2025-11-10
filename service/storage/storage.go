package storage

import (
	"context"
	"encoding/json"

	ecdsa "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsa "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"

	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

const (
	pathEncryptionKey = "encryption.key"
	pathECDSA         = "ecdsa.key"
	pathEdDSA         = "eddsa.key"
)

type Storage struct {
	UserData cfgutil.UserData
}

func (strg *Storage) SaveKeyPair(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	keyPair secutil.EncryptionPrivateKey,
) error {
	plainBs := keyPair.MarshalToBytes()
	encriptedBs, err := ekey.Encrypt(plainBs)
	if err != nil {
		return errutil.Wrap(err)
	}
	return strg.UserData.Save(ctx, encriptedBs, pathEncryptionKey)
}

func (strg *Storage) IsKeyPairExists(
	ctx context.Context,
) (bool, error) {
	_, ok, err := strg.UserData.Load(ctx, pathEncryptionKey)
	if err != nil {
		return false, errutil.Wrap(err)
	}
	return ok, nil
}

func (strg *Storage) LoadKeyPair(
	ctx context.Context,
	ekey secutil.EncryptionKey,
) (secutil.EncryptionPrivateKey, bool, error) {
	encBs, ok, err := strg.UserData.Load(ctx, pathEncryptionKey)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	bs, err := ekey.Decrypt(encBs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	pk, err := secutil.EncryptionPrivateKeyFromBytes(bs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	return pk, true, nil
}

func (strg *Storage) SaveECDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	keys []*ecdsa.LocalPartySaveData,
) error {
	var bsArray [][]byte
	for _, key := range keys {
		bs, err := keyutil.LocalDataToBytesECDSA(ctx, key)
		if err != nil {
			return errutil.Wrap(err)
		}
		bsArray = append(bsArray, bs)
	}
	return strg.saveBsArray(ctx, ekey, bsArray, pathECDSA)
}

func (strg *Storage) LoadECDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
) ([]*ecdsa.LocalPartySaveData, bool, error) {
	bsArray, ok, err := strg.loadBsArray(ctx, ekey, pathECDSA)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	var keys []*ecdsa.LocalPartySaveData
	for _, bs := range bsArray {
		key, err := keyutil.LocalDataFromBytesECDSA(ctx, bs)
		if err != nil {
			return nil, false, errutil.Wrap(err)
		}
		keys = append(keys, key)
	}
	return keys, true, nil
}

func (strg *Storage) SaveEdDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	keys []*eddsa.LocalPartySaveData,
) error {
	var bsArray [][]byte
	for _, key := range keys {
		bs, err := keyutil.LocalDataToBytesEdDSA(ctx, key)
		if err != nil {
			return errutil.Wrap(err)
		}
		bsArray = append(bsArray, bs)
	}
	return strg.saveBsArray(ctx, ekey, bsArray, pathEdDSA)
}

func (strg *Storage) LoadEdDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
) ([]*eddsa.LocalPartySaveData, bool, error) {
	bsArray, ok, err := strg.loadBsArray(ctx, ekey, pathEdDSA)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	var keys []*eddsa.LocalPartySaveData
	for _, bs := range bsArray {
		key, err := keyutil.LocalDataFromBytesEdDSA(ctx, bs)
		if err != nil {
			return nil, false, errutil.Wrap(err)
		}
		keys = append(keys, key)
	}
	return keys, true, nil
}

func (strg *Storage) saveBsArray(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	bsArray [][]byte,
	path ...string,
) error {
	jsonBs, err := json.Marshal(bsArray)
	if err != nil {
		return errutil.Wrap(err)
	}
	encBs, err := ekey.Encrypt(jsonBs)
	if err != nil {
		return errutil.Wrap(err)
	}
	return strg.UserData.Save(ctx, encBs, path...)
}

func (strg *Storage) loadBsArray(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	path ...string,
) ([][]byte, bool, error) {
	encBs, ok, err := strg.UserData.Load(ctx, path...)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	jsonBs, err := ekey.Decrypt(encBs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	var bsArray [][]byte
	if err := json.Unmarshal(jsonBs, &bsArray); err != nil {
		return nil, false, errutil.Wrap(err)
	}
	return bsArray, true, nil
}
