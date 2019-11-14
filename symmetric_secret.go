package gosecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// Ecb 3Des 加密
func (s DesOrAes) EcbDesEncrypt() ([]byte, error) {
	tKey := make([]byte, 24, 24)
	copy(tKey, s.Key)
	k1 := tKey[:8]
	k2 := tKey[8:16]
	k3 := tKey[16:]

	block, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	s.OrigData = s.PKCS5Padding(s.OrigData, bs)

	s.CryptEd, err = s.encrypt(k1)
	if err != nil {
		return nil, err
	}
	s.OrigData, err = s.decrypt(k2)
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
	copy(tKey, s.Key)
	k1 := tKey[:8]
	k2 := tKey[8:16]
	k3 := tKey[16:]

	s.OrigData, err = s.decrypt(k3)
	if err != nil {
		return nil, err
	}
	s.CryptEd, err = s.encrypt(k2)
	if err != nil {
		return nil, err
	}
	s.OrigData, err = s.decrypt(k1)
	if err != nil {
		return nil, err
	}
	out := s.PKCS5UnPadding()
	return out, nil
}

// Cbc 3DES加密

func (s DesOrAes) CbcDesEncrypt() ([]byte, error) {
	block, err := des.NewTripleDESCipher(s.Key)
	if err != nil {
		return nil, err
	}
	s.OrigData = s.PKCS5Padding(s.OrigData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, s.Key[:8])
	cryptEd := make([]byte, len(s.OrigData))
	blockMode.CryptBlocks(cryptEd, s.OrigData)
	return cryptEd, nil
}

// Cbc 3DES解密
func (s DesOrAes) CbcDesDecrypt() ([]byte, error) {
	block, err := des.NewTripleDESCipher(s.Key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, s.Key[:8])
	s.OrigData = make([]byte, len(s.CryptEd))
	blockMode.CryptBlocks(s.OrigData, s.CryptEd)
	origData := s.PKCS5UnPadding()
	return origData, nil
}

// Aes 加密
func (s DesOrAes) AesEncrypt() ([]byte, error) {

	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	s.OrigData = s.PKCS5Padding(s.OrigData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, s.Key[:blockSize])
	cryptEd := make([]byte, len(s.OrigData))
	blockMode.CryptBlocks(cryptEd, s.OrigData)
	return cryptEd, nil
}

// Aes 解密
func (s DesOrAes) AesDecrypt() ([]byte, error) {
	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, s.Key[:blockSize])
	s.OrigData = make([]byte, len(s.CryptEd))
	blockMode.CryptBlocks(s.OrigData, s.CryptEd)
	origData := s.PKCS5UnPadding()
	return origData, nil
}
