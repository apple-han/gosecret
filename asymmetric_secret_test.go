package gosecret

import "testing"

func TestRsa_PrivateSign(t *testing.T) {
	r := Rsa{
		OriginData:[]byte("hello world"),
		Genre: 1,
		Bits:  512,
	}
	content := r.PrivateSign()
	const result = "CatZb56l9kxmYY5AyBHtz8UP2USfT85gaC/Ky/fBD6a2uXYDshgYkNvUDQQPuOFCGFJhvUvAB8e6bbnN1Uxekw=="
	if content != result{
		t.Errorf("result should have %s "+
			";but had %s", result, content)
	}
}

func TestRsa_PublicCheckSign(t *testing.T) {
	r := Rsa{
		SignData:[]byte("CatZb56l9kxmYY5AyBHtz8UP2USfT85gaC/Ky/fBD6a2uXYDshgYkNvUDQQPuOFCGFJhvUvAB8e6bbnN1Uxekw=="),
		Genre: 1,
	}
	err := r.PublicCheckSign()
	if err != nil{
		t.Errorf("check sign fail")
	}
}

func TestRsa_PubEncrypt(t *testing.T) {
	r := Rsa{
		OriginData:[]byte("hello world"),
		Bits:  512,

	}
	content, err := r.PubEncrypt()
	if err != nil{
		panic(err)
	}
	const result = "glD1f9uLvV4c2UOk7OX1leB+mhmRYjedDbN0OmTOZ6/sfRTeidY0YEByFUUhcJRtl0DFhiVsCIVrUkD3CzO9Vg=="
	if content != result{
		t.Errorf("result should have %s "+
			";but had %s", result, content)
	}
}

func TestRsa_PriDecrypt(t *testing.T) {
	r := Rsa{
		DecryptData:[]byte("glD1f9uLvV4c2UOk7OX1leB+mhmRYjedDbN0OmTOZ6/sfRTeidY0YEByFUUhcJRtl0DFhiVsCIVrUkD3CzO9Vg=="),
		Bits:  512,
	}

	content, err := r.PriDecrypt()
	if err != nil{
		panic(err)
	}
	const result = "hello world"
	if content != result{
		t.Errorf("result should have %s "+
			";but had %s", result, content)
	}
}

func TestRsa_PriEncrypt(t *testing.T) {
	r := Rsa{
		OriginData:[]byte("hello world"),
		Bits:  512,

	}
	content, err := r.PriEncrypt()
	if err != nil{
		panic(err)
	}
	const result = "pAWY90YLlNk7etWIlYUUV351DAI76Rt3SEYrqb4pInzD35fbrQC8wPncZXm4vJ3ReBPj8GYbHHDUYyUxHfNbpw=="
	if content != result{
		t.Errorf("result should have %s "+
			";but had %s", result, content)
	}
}

func TestRsa_PubDecrypt(t *testing.T) {
	r := Rsa{
		DecryptData:[]byte("pAWY90YLlNk7etWIlYUUV351DAI76Rt3SEYrqb4pInzD35fbrQC8wPncZXm4vJ3ReBPj8GYbHHDUYyUxHfNbpw=="),
		Bits:  512,
	}

	content, err := r.PubDecrypt()
	if err != nil{
		panic(err)
	}
	const result = "hello world"
	if content != result{
		t.Errorf("result should have %s "+
			";but had %s", result, content)
	}
}