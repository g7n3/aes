package main

import (
	"fmt"
	"goaes"
)

func main() {
	aesEnc := goaes.NewEnc()
	aesEnc.Iv = `sdf234wef34efrfT1`
	aesEnc.Key = `aaC5p6c5L2g6KeJdf`
	source := `i want go`
	des, err := aesEnc.Encrypt(source)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("hahaha watele")
	}
	resource, err := aesEnc.Decrypt(des)
	fmt.Println(resource)
}
