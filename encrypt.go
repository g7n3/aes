package goaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type AesEncrypt struct {
	Key string
	Iv  string
}

func NewEnc() *AesEncrypt {
	return &AesEncrypt{}
}

func (this *AesEncrypt) getKey() ([]byte, error) {

	keyLen := len(this.Key)
	if keyLen < 16 {
		return []byte(""), errors.New("res key 长度不能小于16")
	}
	arrKey := []byte(this.Key)
	if keyLen >= 32 {
		//取前32个字节
		return arrKey[:32], nil
	}
	if keyLen >= 24 {
		//取前24个字节
		return arrKey[:24], nil
	}
	//取前16个字节
	return arrKey[:16], nil
}

//加密字符串
func (this *AesEncrypt) Encrypt(strMesg string) ([]byte, error) {

	plantText := []byte(strMesg)

	key, errs := this.getKey()
	if errs != nil {
		return nil, errs
	}
	block, err := aes.NewCipher(key) //选择加密算法
	if err != nil {
		return nil, err
	}
	plantText = this.PKCS7Padding(plantText, block.BlockSize())

	blockModel := cipher.NewCBCEncrypter(block, []byte(this.Iv)[:aes.BlockSize])

	ciphertext := make([]byte, len(plantText))

	blockModel.CryptBlocks(ciphertext, plantText)
	return ciphertext, nil
}

//解密字符串
func (this *AesEncrypt) Decrypt(src []byte) (strDesc string, err error) {

	defer func() {
		//错误处理
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	key, errs := this.getKey()
	if errs != nil {
		return "", errs
	}
	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes) //选择加密算法
	if err != nil {
		return "", err
	}
	blockModel := cipher.NewCBCDecrypter(block, []byte(this.Iv)[:aes.BlockSize])
	plantText := make([]byte, len(src))
	blockModel.CryptBlocks(plantText, src)
	plantText = this.PKCS7UnPadding(plantText, block.BlockSize())
	return string(plantText), nil
}

//补位
func (this *AesEncrypt) PKCS7UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

//补位
func (this *AesEncrypt) PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
