package gosecret

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"fmt"
	"github.com/wenzhenxi/gorsa"
	"log"
	"os"

	"github.com/apple-han/gosecret/file"

	"errors"
)

//PrivateSign 私钥加签
func(r Rsa) PrivateSign() string {

	if err := r.GenRsaKey(r.bits); err != nil {
		log.Fatal("密钥文件生成失败！", err)
	}

	log.Println("密钥文件生成成功！")
	goPath := os.Getenv("GOPATH")

	data, err := file.ReadAll(goPath+"/src/github.com/apple-han/gosecret/private.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode([]byte(data))
	if block == nil {
		fmt.Println("block是空的")
		return ""
	}

	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	priKey := private.(*rsa.PrivateKey)
	if err != nil {
		log.Println("无法还原私钥")
		return ""
	}
	result := ""
	switch {
	case r.genre == 1:
		result = r.md5(priKey)
	case r.genre == 2:
		result = r.sha1(priKey)
	case r.genre == 3:
		result = r.sha256(priKey)
	}
	return result
}

// PublicCheckSign 公钥验签
func(r Rsa) PublicCheckSign() error{
	// 获取公钥
	goPath := os.Getenv("GOPATH")
	data, err := file.ReadAll(goPath+"/src/github.com/apple-han/gosecret/public.pem")

	sign, err := base64.StdEncoding.DecodeString(string(r.SignData))
	if err != nil {
		return errors.New("解析出错了!")
	}
	m := strings.Replace(string(data), "-----BEGIN 公钥-----", "", -1)
	p := strings.Replace(m, "-----END 公钥-----", "", -1)

	public, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return errors.New("公钥不正确!")
	}

	fmt.Println(public)
	pub, err := x509.ParsePKIXPublicKey(public)
	if err != nil {
		fmt.Println(err)
		fmt.Println("eeeewww")
		return errors.New("公钥不正确!")
	}
	c := crypto.MD5
	hash := md5.New()
	switch {
	case r.genre == 1:
		c = crypto.MD5
		hash = md5.New()
	case r.genre == 2:
		c = crypto.SHA1
		hash = sha1.New()
	case r.genre == 3:
		c = crypto.SHA256
		hash = sha256.New()
	}
	hash.Write([]byte(r.OriginData))
	fmt.Println("eeeee")
	err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), c, hash.Sum(nil), sign)
	if err == nil{
		log.Println("恭喜你验签成功,开始做其他的事情吧^_^")
	}
	return nil
}

// applyPubEPriD 公钥加密 私钥解密
func(r Rsa) PubEncrypt()(string, error){
	if err := r.GenRsaKey(r.bits); err != nil {
		log.Fatal("密钥文件生成失败！", err)
	}

	log.Println("密钥文件生成成功！")
	goPath := os.Getenv("GOPATH")

	data, err := file.ReadAll(goPath+"/src/github.com/apple-han/gosecret/public.pem")
	if err != nil {
		panic(err)
	}

	pubEncrypt, err := gorsa.PublicEncrypt(string(r.OriginData), string(data))
	if err != nil {
		return "", errors.New("公钥加密失败")
	}
	return pubEncrypt, nil
}

func(r Rsa) PriDecrypt() (string, error) {
	goPath := os.Getenv("GOPATH")
	data, err := file.ReadAll(goPath+"/src/github.com/apple-han/gosecret/private.pem")
	if err != nil {
		panic(err)
	}

	priDecrypt, err := gorsa.PriKeyDecrypt(string(r.DecryptData), string(data))
	if err != nil {
		return "", errors.New("私钥解密失败")
	}
	return priDecrypt, nil
}


// PubDecrypt 公钥解密 PriEncrypt 私钥加密
func(r Rsa) PriEncrypt() (string,error) {
	if err := r.GenRsaKey(r.bits); err != nil {
		log.Fatal("密钥文件生成失败！", err)
	}

	log.Println("密钥文件生成成功！")
	goPath := os.Getenv("GOPATH")
	data, err := file.ReadAll(goPath+"/src/github.com/apple-han/gosecret/private.pem")
	privateEncrypt, err := gorsa.PriKeyEncrypt(string(r.OriginData) ,string(data))
	if err != nil {
		return "", errors.New("私钥加密失败")
	}
	return privateEncrypt, nil
}

func(r Rsa) PubDecrypt() (string,error) {
	goPath := os.Getenv("GOPATH")
	data, err := file.ReadAll(goPath+"/src/github.com/apple-han/gosecret/public.pem")
	pubDecrypt, err := gorsa.PublicDecrypt(string(r.DecryptData), string(data))
	if err != nil {
		fmt.Println(err)
		return "", errors.New("公钥解密失败")
	}

	return pubDecrypt, nil
}