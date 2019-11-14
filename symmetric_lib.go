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
	OrigData   []byte  //初始的数据
	Key        []byte  // 加密的秘钥
	CryptEd    []byte  // 被解密的数据
}

func (s DesOrAes) PKCS5UnPadding() []byte {
	length := len(s.OrigData)
	unPadding := int(s.OrigData[length-1])
	return s.OrigData[:(length - unPadding)]
}

func (s DesOrAes) PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func (s DesOrAes) encrypt(key []byte) ([]byte, error) {
	if len(s.OrigData) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(s.OrigData)%bs != 0 {
		return nil, errors.New("wrong padding")
	}
	out := make([]byte, len(s.OrigData))
	dst := out
	for len(s.OrigData) > 0 {
		block.Encrypt(dst, s.OrigData[:bs])
		s.OrigData = s.OrigData[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func (s DesOrAes) decrypt(key []byte) ([]byte, error) {
	if len(s.CryptEd) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(s.CryptEd))
	dst := out
	bs := block.BlockSize()
	if len(s.CryptEd)%bs != 0 {
		return nil, errors.New("wrong cryptEd size")
	}

	for len(s.CryptEd) > 0 {
		block.Decrypt(dst, s.CryptEd[:bs])
		s.CryptEd = s.CryptEd[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func (s DesOrAes) CbcEncrypt(key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	s.OrigData = s.PKCS5Padding(s.OrigData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	cryptEd := make([]byte, len(s.OrigData))
	blockMode.CryptBlocks(cryptEd, s.OrigData)
	return cryptEd, nil
}

func (s DesOrAes) CbcDecrypt(key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	s.OrigData = make([]byte, len(s.CryptEd))
	blockMode.CryptBlocks(s.OrigData, s.CryptEd)
	origData := s.PKCS5UnPadding()
	return origData, nil
}
