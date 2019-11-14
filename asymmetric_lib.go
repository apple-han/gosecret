package gosecret

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
)

type Rsa struct {
	OriginData []byte // 初始数据
	SignData   []byte // 等待验签的数据
	Genre      int    // 加密的类型
	Bits       int    // 秘钥的长度
	DecryptData []byte // 解密的数据
}

func (r Rsa) GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream, err := x509.MarshalPKCS8PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	file, err := os.Create("./private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	file, err = os.Create("./public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}
func (r Rsa) md5(p *rsa.PrivateKey) string {
	h2 := md5.New()
	h2.Write(r.OriginData)
	hashed := h2.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, p, crypto.MD5, hashed)
	if err != nil {
		log.Println("秘钥加签失败")
	}
	encodeString := base64.StdEncoding.EncodeToString(sign)
	return encodeString
}

func (r Rsa) sha1(p *rsa.PrivateKey) string {
	h := sha1.New()
	h.Write([]byte(r.OriginData))
	hash := h.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA1, hash[:])
	if err != nil {
		log.Println("秘钥加签失败")
	}
	encodeString := base64.StdEncoding.EncodeToString(sign)
	return encodeString
}

func (r Rsa) sha256(p *rsa.PrivateKey) string {
	h := sha256.New()
	h.Write([]byte(r.OriginData))
	hash := h.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA256, hash[:])
	if err != nil {
		log.Println("秘钥加签失败")
	}
	encodeString := base64.StdEncoding.EncodeToString(sign)
	return encodeString
}

