# gosearch: Make secret extremely simple™

![image](https://farm5.staticflickr.com/4695/39152770914_a3ab8af40d_k_d.jpg)
## Requirements
- Go development environment: >= go1.2

### Install from source code
    go get -u github.com/apple-han/gosecret \
              github.com/wenzhenxi/gorsa

## Why do this?
- 加密的种类很多, 每次找都很麻烦.
- 非常常见的功能, 应该隐藏掉容易出错的细节.
## Fearture
- 对称加密.
- 非对称加密.
## Tutorial & Usage
```
// 对称加密
// Aes 加密
d := DesOrAes{
	origData: []byte("hello world"),  // 需要加密的数据
	key     : []byte("smkldospdosldaaa"), // 加密所需要的key
}
contents,err := d.AesEncrypt()
// Aes 解密
d := DesOrAes{
	cryptEd : []byte("2kka6xb8T2uMf7Uj+BNISQ=="), # 被加密过的结果(默认用base64 to string了)
	key     : []byte("smkldospdosldaaa"), 
}
contents,err := d.AesDecrypt()

// des cbc 加密
d := DesOrAes{
	OrigData: []byte("hello world"),
	Key     : []byte("123456789012345678901234"),
}
contents,err := d.CbcDesEncrypt()

// des cbc 解密
d := DesOrAes{
	CryptEd: []byte("WJ+EfR2QSeRw87h8u1yGbw=="),
	Key     : []byte("123456789012345678901234"),
}
r, err := base64.StdEncoding.DecodeString(string(d.cryptEd))
d.cryptEd = r
contents,err := d.CbcDesDecrypt()

// des ecb 加密
d := DesOrAes{
	OrigData: []byte("hello world"),
	Key     : []byte("123456789012345678901234"),
}
contents,err := d.EcbDesEncrypt()

// des ecb 解密
d := DesOrAes{
	CryptEd: []byte("SdHQCpbVRzk4JSGbnhUMLg=="),
	Key     : []byte("123456789012345678901234"),
}
r, err := base64.StdEncoding.DecodeString(string(d.cryptEd))
d.cryptEd = r
contents,err := d.EcbDesDecrypt()


// 非对称加密
// 私钥加签
r := Rsa{
	OriginData:[]byte("hello world"), // 需要加签的数据
	Genre: 1,                         // 加签的类型(1:md5 2:sha1 3:sha356)
	Bits:  512,                       // 生成秘钥的长度(512, 1024, 等)
}
content := r.PrivateSign()

// 公钥验签
r := Rsa{
	SignData:[]byte() // 已经被加签的数据
	Genre: 1,         // 加签的类型(1:md5 2:sha1 3:sha356)
}
err := r.PublicCheckSign()  // err 为nil 说明验签成功


// 公钥加密
r := Rsa{
	OriginData:[]byte("hello world"),
	Bits:  512,
}
content, err := r.PubEncrypt()

// 私钥解密
r := Rsa{
	DecryptData:[]byte(), // 已经被加密的数据
	Bits:  512,
}
content, err := r.PriDecrypt()

// 私钥加密
r := Rsa{
	OriginData:[]byte("hello world"),
	Bits:  512,
}
content, err := r.PriEncrypt()

// 公钥解密
r := Rsa{
	DecryptData:[]byte(), // 已经被加密的数据
	Bits:  512,
}
content, err := r.PubDecrypt()
```

## License

This project is under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full license text.

