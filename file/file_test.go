package file

import (
	"testing"
)

func TestReadAll(t *testing.T) {
	contents, err := ReadAll("./test.txt")

	if err != nil{
		panic(err)
	}

	const result = "hello gosecret"

	if string(contents) != result{
		t.Errorf("result should have %s "+
			";but had %s", result, contents)
	}
}