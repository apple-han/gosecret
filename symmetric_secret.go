package gosecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// Ecb 3Des 加密
func (s DesOrAes) EcbDesEncrypt() ([]byte, error) {
	tKey := make([]byte, 24, 24)
	copy(tKey, s.key)
	k1 := tKey[:8]
	k2 := tKey[8:16]
	k3 := tKey[16:]

	block, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	s.origData = s.PKCS5Padding(s.origData, bs)

	s.cryptEd, err = s.encrypt(k1)
	if err != nil {
		return nil, err
	}
	s.origData, err = s.decrypt(k2)
	if err != nil {
		return nil, err
	}
	out, err := s.encrypt(k3)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Ecb 3Des 解密
func (s DesOrAes) EcbDesDecrypt() (b []byte, err error) {
	tKey := make([]byte, 24, 24)
	copy(tKey, s.key)
	k1 := tKey[:8]
	k2 := tKey[8:16]
	k3 := tKey[16:]

	s.origData, err = s.decrypt(k3)
	if err != nil {
		return nil, err
	}
	s.cryptEd, err = s.encrypt(k2)
	if err != nil {
		return nil, err
	}
	s.origData, err = s.decrypt(k1)
	if err != nil {
		return nil, err
	}
	out := s.PKCS5UnPadding()
	return out, nil
}

// Cbc 3DES加密

func (s DesOrAes) CbcDesEncrypt() ([]byte, error) {
	block, err := des.NewTripleDESCipher(s.key)
	if err != nil {
		return nil, err
	}
	s.origData = s.PKCS5Padding(s.origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, s.key[:8])
	cryptEd := make([]byte, len(s.origData))
	blockMode.CryptBlocks(cryptEd, s.origData)
	return cryptEd, nil
}

// Cbc 3DES解密
func (s DesOrAes) CbcDesDecrypt() ([]byte, error) {
	block, err := des.NewTripleDESCipher(s.key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, s.key[:8])
	s.origData = make([]byte, len(s.cryptEd))
	blockMode.CryptBlocks(s.origData, s.cryptEd)
	origData := s.PKCS5UnPadding()
	return origData, nil
}

// Aes 加密
func (s DesOrAes) AesEncrypt() ([]byte, error) {

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	s.origData = s.PKCS5Padding(s.origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, s.key[:blockSize])
	cryptEd := make([]byte, len(s.origData))
	blockMode.CryptBlocks(cryptEd, s.origData)
	return cryptEd, nil
}

// Aes 解密
func (s DesOrAes) AesDecrypt() ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, s.key[:blockSize])
	s.origData = make([]byte, len(s.cryptEd))
	blockMode.CryptBlocks(s.origData, s.cryptEd)
	origData := s.PKCS5UnPadding()
	return origData, nil
}
