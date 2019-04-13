package gosecret

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"errors"
)

type SymmetricEncryption interface {
	PKCS5UnPadding() []byte
	PKCS5Padding() []byte
	Decrypt() []byte
	Encrypt() []byte
	CbcDecrypt() []byte
	CbcEncrypt() []byte
}

type DesOrAes struct {
	origData   []byte  //初始的数据
	key        []byte  // 加密的秘钥
	cryptEd    []byte  // 被解密的数据
}

func (s DesOrAes) PKCS5UnPadding() []byte {
	length := len(s.origData)
	unPadding := int(s.origData[length-1])
	return s.origData[:(length - unPadding)]
}

func (s DesOrAes) PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func (s DesOrAes) encrypt(key []byte) ([]byte, error) {
	if len(s.origData) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(s.origData)%bs != 0 {
		return nil, errors.New("wrong padding")
	}
	out := make([]byte, len(s.origData))
	dst := out
	for len(s.origData) > 0 {
		block.Encrypt(dst, s.origData[:bs])
		s.origData = s.origData[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func (s DesOrAes) decrypt(key []byte) ([]byte, error) {
	if len(s.cryptEd) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(s.cryptEd))
	dst := out
	bs := block.BlockSize()
	if len(s.cryptEd)%bs != 0 {
		return nil, errors.New("wrong cryptEd size")
	}

	for len(s.cryptEd) > 0 {
		block.Decrypt(dst, s.cryptEd[:bs])
		s.cryptEd = s.cryptEd[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func (s DesOrAes) CbcEncrypt(key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	s.origData = s.PKCS5Padding(s.origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	cryptEd := make([]byte, len(s.origData))
	blockMode.CryptBlocks(cryptEd, s.origData)
	return cryptEd, nil
}

func (s DesOrAes) CbcDecrypt(key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	s.origData = make([]byte, len(s.cryptEd))
	blockMode.CryptBlocks(s.origData, s.cryptEd)
	origData := s.PKCS5UnPadding()
	return origData, nil
}
