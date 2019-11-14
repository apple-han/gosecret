package gosecret

import (
	"encoding/base64"
	"testing"
)

func TestDesOrAes_AesEncrypt(t *testing.T) {
	d := DesOrAes{
		OrigData: []byte("hello world"),
		Key     : []byte("smkldospdosldaaa"),
	}
	contents,err := d.AesEncrypt()
	c := base64.StdEncoding.EncodeToString(contents)
	const result = "2kka6xb8T2uMf7Uj+BNISQ=="

	if err != nil{
		t.Errorf("result should have %s "+
			";but had %s", result, c)
	}
}

func TestDesOrAes_AesDecrypt(t *testing.T) {
	d := DesOrAes{
		CryptEd: []byte("2kka6xb8T2uMf7Uj+BNISQ=="),
		Key     : []byte("smkldospdosldaaa"),
	}
	r, err := base64.StdEncoding.DecodeString(string(d.CryptEd))
	d.CryptEd = r
	contents,err := d.AesDecrypt()
	const result = "hello world"

	if err != nil{
		t.Errorf("result should have %s "+
			";but had %s", result, contents)
	}
}

func TestDesOrAes_CbcDesEncrypt(t *testing.T) {
	d := DesOrAes{
		OrigData: []byte("hello world"),
		Key     : []byte("123456789012345678901234"),
	}
	contents,err := d.CbcDesEncrypt()
	c := base64.StdEncoding.EncodeToString(contents)
	const result = "WJ+EfR2QSeRw87h8u1yGbw=="
	if err != nil{
		t.Errorf("result should have %s "+
			";but had %s", result, c)
	}
}

func TestDesOrAes_CbcDesDecrypt(t *testing.T) {
	d := DesOrAes{
		CryptEd: []byte("WJ+EfR2QSeRw87h8u1yGbw=="),
		Key     : []byte("123456789012345678901234"),
	}
	r, err := base64.StdEncoding.DecodeString(string(d.CryptEd))
	d.CryptEd = r
	contents,err := d.CbcDesDecrypt()
	const result = "hello world"
	if err != nil{
		t.Errorf("result should have %s "+
			";but had %s", result, contents)
	}
}

func TestDesOrAes_EcbDesEncrypt(t *testing.T) {
	d := DesOrAes{
		OrigData: []byte("hello world"),
		Key     : []byte("123456789012345678901234"),
	}
	contents,err := d.EcbDesEncrypt()
	c := base64.StdEncoding.EncodeToString(contents)
	const result = "SdHQCpbVRzk4JSGbnhUMLg=="
	if err != nil{
		t.Errorf("result should have %s "+
			";but had %s", result, c)
	}
}

func TestDesOrAes_EcbDesDecrypt(t *testing.T) {
	d := DesOrAes{
		CryptEd: []byte("SdHQCpbVRzk4JSGbnhUMLg=="),
		Key     : []byte("123456789012345678901234"),
	}
	r, err := base64.StdEncoding.DecodeString(string(d.CryptEd))
	d.CryptEd = r
	contents,err := d.EcbDesDecrypt()

	const result = "hello world"
	if err != nil{
		t.Errorf("result should have %s "+
			";but had %s", result, contents)
	}
}