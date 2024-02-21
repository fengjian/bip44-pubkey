package main

import (
	"flag"
	"fmt"
	"log"
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	bip39 "github.com/tyler-smith/go-bip39"
	bip32 "github.com/tyler-smith/go-bip32"
)

const (
	// HardenedKeyStart is the start index of hardened keys.
	HardenedKeyStart = uint32(0x80000000)
)

func main() {
	// 定义命令行参数 -mnemonic，用于接收助记词
	mnemonic := flag.String("mnemonic", "", "助记词")
	index := flag.Int("index", 0, "index")
	passphrase := flag.String("passphrase", "", "passphrase")

	flag.Parse()

	// 检查助记词是否为空
	if *mnemonic == "" {
		fmt.Println("请提供助记词作为命令行参数 -mnemonic 的值")
		return
	}

	// 使用 BIP39 生成种子
	seed := bip39.NewSeed(*mnemonic, *passphrase)

	// 使用 BIP32 生成主密钥
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatal("生成主密钥失败:", err)
	}

	// 定义 BIP44 路径：m/44'/60'/0'/0/0
	// m: 主密钥
	// 44': BIP44规定的币种标识（以太坊为 60'，主网）
	// 0'/0/0: 账户索引（这里选择使用第一个账户），外部/内部索引（0 表示外部，1 表示内部），索引（第一个地址）
	path := []uint32{44 + HardenedKeyStart, 60 + HardenedKeyStart, 0 + HardenedKeyStart, 0, uint32(*index)}

	// 使用 BIP32 生成派生密钥
	childKey := masterKey
	for _, index := range path {
		childKey, err = childKey.NewChildKey(index)
		if err != nil {
			log.Fatal("生成派生密钥失败:", err)
		}
	}

	// 使用派生密钥生成以太坊地址
	privateKeyECDSA, err := crypto.ToECDSA(childKey.Key)
	if err != nil {
		log.Fatal("转换为ECDSA私钥失败:", err)
	}
	pubKey := privateKeyECDSA.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*pubKey).Hex()
	fmt.Println("以太坊地址:", address)
}
