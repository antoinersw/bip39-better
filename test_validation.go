package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

func loadWords(path string) []string {
	words := make([]string, 0, 2048)
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}
	return words
}

func computeChecksum(entropy []byte) *big.Int {
	checksumBits := uint(len(entropy) / 4)
	hash := sha256.Sum256(entropy)
	checksum := new(big.Int).SetBytes(hash[:])
	checksum.Rsh(checksum, uint(len(hash)*8)-checksumBits)
	return checksum
}

func isValidMnemonic(mnemonic []string, reverseWords map[string]int) bool {
	if len(mnemonic) != 24 {
		return false
	}

	// Check if all words are in the wordlist
	for _, word := range mnemonic {
		if _, ok := reverseWords[word]; !ok {
			return false
		}
	}

	// Convert mnemonic to big integer
	bytes := new(big.Int)
	for _, word := range mnemonic {
		bytes.Lsh(bytes, 11)
		bytes.Add(bytes, big.NewInt(int64(reverseWords[word])))
	}

	// For 24 words: 8 checksum bits
	checksumBits := 8
	checksum := new(big.Int)
	bytes.DivMod(bytes, big.NewInt(1<<checksumBits), checksum)

	// Get entropy bytes (should be 32 bytes for 256 bits)
	entropyBytes := bytes.Bytes()
	
	// Pad to exactly 32 bytes if necessary
	if len(entropyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(entropyBytes):], entropyBytes)
		entropyBytes = padded
	} else if len(entropyBytes) > 32 {
		// Take only the last 32 bytes
		entropyBytes = entropyBytes[len(entropyBytes)-32:]
	}

	expectedChecksum := computeChecksum(entropyBytes)
	return checksum.Cmp(expectedChecksum) == 0
}

func main() {
	fmt.Println("Testing BIP39 24-word mnemonic validation...")
	
	wordList := loadWords("english-wordlist.txt")
	reverseWords := make(map[string]int)
	for i, word := range wordList {
		reverseWords[word] = i
	}

	// Test with some known valid 24-word mnemonics
	testMnemonics := []string{
		// You can add known valid 24-word mnemonics here for testing
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
	}

	for i, mnemonicStr := range testMnemonics {
		mnemonic := strings.Split(mnemonicStr, " ")
		fmt.Printf("Testing mnemonic %d: %s\n", i+1, mnemonicStr)
		
		if isValidMnemonic(mnemonic, reverseWords) {
			fmt.Printf("✅ Mnemonic %d is VALID\n", i+1)
		} else {
			fmt.Printf("❌ Mnemonic %d is INVALID\n", i+1)
		}
		fmt.Println()
	}

	fmt.Println("Validation test completed!")
} 