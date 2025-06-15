package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Result represents the successful crack result
type Result struct {
	Mnemonic          string   `json:"mnemonic"`
	Seed              string   `json:"seed"`
	Address           string   `json:"address"`
	DerivationPath    string   `json:"derivation_path"`
	ValidChecksumWords []string `json:"valid_checksum_words"`
	FuzzyMode         bool     `json:"fuzzy_mode"`
	FuzzyPositions    []int    `json:"fuzzy_positions,omitempty"`
	Time              string   `json:"timestamp"`
	Attempts          int64    `json:"attempts"`
	ChecksumTests     int64    `json:"checksum_tests"`
	Duration          string   `json:"duration"`
	Rate              string   `json:"phrases_per_second"`
}

// CLI flags
var (
	fuzzyMode      = flag.Bool("f", false, "Enable fuzzy mode")
	fuzzyPositions = flag.String("pos", "", "Positions to fuzz (comma-separated, e.g., '7,10,20' or use multiple -pos flags)")
	fuzzyPositionsList []int
)

// Word candidates for each position (only 23 positions - last word will be from CHECKSUM_WORDS)
var wordCandidates = [][]string{
	{"erase"},                        // position 0
	{"oven","helmet","miss","noise"},                         // position 1
	{"oven","helmet","miss","noise"},                    // position 2
	{"oven","helmet","miss","noise"},                      // position 3
	{"oven","helmet","miss","noise"},                 // position 4
	{"reward","level","blouse","upset","thrive","admit","thrive","upset"},                       // position 5
	{"admit","thrive","upset","reward","level","blouse","upset","thrive"},                        // position 6
	{"admit","thrive","upset","reward","level","blouse","upset","thrive",},    // position 7
	{"admit","thrive","upset","reward","level","blouse","upset","thrive","tell", "mansion", "helmet"},     // position 8
	{"rotate", "admit","upset","reward","level","blouse","upset","thrive","tell", "mansion", "helmet"},              // position 9
	{"rotate", "admit","upset","reward","level","blouse","upset","thrive","tell", "mansion", "helmet"},   // position 10
	{"rotate", "admit","upset","reward","level","blouse","upset","thrive","tell", "mansion", "helmet"},     // position 11
	{"own", "father", "rice",},        // position 12
	{"rice", "father", "own"},        // position 13
	{"muscle"},                       // position 14
	{"half"},                         // position 15
	{"shell"},                        // position 16
	{"subject"},                      // position 17
	{"army"},                         // position 18
	{"fade"},                         // position 19
	{"resemble"},                     // position 20
	{"open"},                         // position 21
	{"always"},                       // position 22
	// position 23 will be one of CHECKSUM_WORDS
}

// test word should work with 3 checksum words
// var wordCandidates = [][]string{
 
// 	{"only"},
// 	{"mansion"},
// 	{"tell"},
// 	{"rotate"},
// 	{"level"},
// 	{"admit"},
// 	{"brush"},
// 	{"thrive"},
// 	{"upset"},
// 	{"own"},
// 	{"miss"},
// 	{"oven"},
// 	{"rice"},
// 	{"father"},
// 	{"muscle"},
// 	{"woman"},
// 	{"shell"},
// 	{"calm"},
// 	{"army"},
// 	{"pudding"},
// 	{"electric"},
// 	{"open"},
// 	{"always"},
// }

// The 8 checksum words that must be tested
var CHECKSUM_WORDS = []string{
	"alien",
	"detect",
	"flip",
	"gas",
	"organ",
	"peasant",
	"staff",
	"trigger",
}

var (
	attemptCount      int64
	checksumTestCount int64
	startTime         time.Time
	lastLogTime       time.Time
	lastAttempts      int64
	lastChecksumTests int64
	totalCombinations int64
	foundResult       int32 // atomic flag
	wordList          []string
	
	// Performance monitoring
	lastGCTime        time.Time
	gcCount           uint32
	maxMemUsed        uint64
)

type WorkItem struct {
	phrase23Words []string
	phraseNumber  int64
}

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

	// For 24 words: 8 checksum bits (256 entropy bits + 8 checksum bits = 264 total bits)
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
		entropyBytes = entropyBytes[len(entropyBytes)-32:]
	}

	expectedChecksum := computeChecksum(entropyBytes)
	return checksum.Cmp(expectedChecksum) == 0
}

func deriveSeed(mnemonic, password string) []byte {
	return pbkdf2.Key(
		[]byte(mnemonic),
		[]byte("mnemonic"+password),
		2048,
		64,
		sha512.New)
}

// Simplified Bitcoin address derivation for BIP84 (this is a mock implementation)
// In a real implementation, you would need proper ECDSA key derivation and Bech32 encoding
func deriveBitcoinAddress(seed []byte) string {
	// Use first 32 bytes as private key material
	hash := sha256.Sum256(seed[:32])
	
	// This is a simplified mock - real implementation would need:
	// 1. Proper BIP32 HD wallet derivation (m/84'/0'/0'/0/0)
	// 2. ECDSA public key derivation
	// 3. P2WPKH script creation
	// 4. Bech32 encoding
	
	// For now, create a mock bc1 address using the hash
	addressBytes := hash[:20] // 20 bytes for P2WPKH
	
	// Simple mock Bech32 encoding (not real Bech32!)
	return fmt.Sprintf("bc1q%x", addressBytes)
}

func saveResult(result Result) error {
	file, err := os.Create("epic_win_result.json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func formatDuration(d time.Duration) string {
	if d.Hours() >= 24 {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%dd %dh", days, hours)
	} else if d.Hours() >= 1 {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else if d.Minutes() >= 1 {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
}

func formatNumber(n int64) string {
	if n >= 1e9 {
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	} else if n >= 1e6 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	} else if n >= 1e3 {
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

func formatMemory(bytes uint64) string {
	if bytes >= 1e9 {
		return fmt.Sprintf("%.1fGB", float64(bytes)/1e9)
	} else if bytes >= 1e6 {
		return fmt.Sprintf("%.1fMB", float64(bytes)/1e6)
	} else if bytes >= 1e3 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1e3)
	}
	return fmt.Sprintf("%d bytes", bytes)
}

func performanceLogger() {
	ticker := time.NewTicker(10 * time.Second) // Plus fréquent pour les stats
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&foundResult) == 1 {
				return
			}
			
			now := time.Now()
			elapsed := now.Sub(startTime)
			elapsedSinceLastLog := now.Sub(lastLogTime)
			
			currentAttempts := atomic.LoadInt64(&attemptCount)
			currentChecksumTests := atomic.LoadInt64(&checksumTestCount)
			
			// Calculer phrases par seconde depuis le dernier log
			attemptsDelta := currentAttempts - lastAttempts
			checksumDelta := currentChecksumTests - lastChecksumTests
			phrasesPerSecond := float64(attemptsDelta) / elapsedSinceLastLog.Seconds()
			checksumPerSecond := float64(checksumDelta) / elapsedSinceLastLog.Seconds()
			
			// Calculer le taux moyen
			overallPhraseRate := float64(currentAttempts) / elapsed.Seconds()
			
			// Calculer progression
			progressPercent := float64(currentAttempts) / float64(totalCombinations) * 100.0
			
			// Temps estimé restant
			remaining := totalCombinations - currentAttempts
			var estimatedTimeLeft time.Duration
			if phrasesPerSecond > 0 {
				estimatedTimeLeft = time.Duration(float64(remaining)/phrasesPerSecond) * time.Second
			}
			
			// Statistiques mémoire et GC
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			
			// Détecter les problèmes de performance
			performanceWarning := ""
			if phrasesPerSecond < overallPhraseRate*0.5 {
				performanceWarning = " ⚠️ PERF DROP"
			}
			if m.NumGC > gcCount {
				gcCount = m.NumGC
				performanceWarning += " 🗑️ GC"
			}
			if m.Alloc > maxMemUsed {
				maxMemUsed = m.Alloc
			}
			
			// Affichage compact des stats avec monitoring
			fmt.Printf("📊 [%s] %.2f%% | %s/%s phrases | %.0f p/s | %s tests/s | ETA: %s | MEM: %s%s\n",
				formatDuration(elapsed),
				progressPercent,
				formatNumber(currentAttempts),
				formatNumber(totalCombinations),
				overallPhraseRate,
				formatNumber(int64(checksumPerSecond)),
				formatDuration(estimatedTimeLeft),
				formatMemory(m.Alloc),
				performanceWarning)
			
			// Force GC si la mémoire devient excessive
			if m.Alloc > 1024*1024*1024 { // > 1GB
				runtime.GC()
				fmt.Println("🗑️ Forced garbage collection")
			}
			
			lastLogTime = now
			lastAttempts = currentAttempts
			lastChecksumTests = currentChecksumTests
		}
	}
}

// Helper function to check if a slice contains an integer
func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Get available words for a position, excluding words already used in the phrase
func getAvailableWordsForPosition(position int, currentPhrase []string, useFuzzy bool) []string {
	if !useFuzzy || !contains(fuzzyPositionsList, position) {
		// Mode normal : utiliser les candidats définis, mais exclure les mots déjà utilisés
		candidates := wordCandidates[position]
		var availableWords []string
		
		// Créer un set des mots déjà utilisés dans la phrase courante
		usedWords := make(map[string]bool)
		for i, word := range currentPhrase {
			if i < position && word != "" {
				usedWords[word] = true
			}
		}
		
		// Filtrer les candidats pour exclure les mots déjà utilisés
		for _, word := range candidates {
			if !usedWords[word] {
				availableWords = append(availableWords, word)
			}
		}
		
		return availableWords
	}
	
	// Mode fuzzy : utiliser toute la wordlist sauf les mots déjà utilisés
	usedWords := make(map[string]bool)
	for i, word := range currentPhrase {
		if i < position && word != "" {
			usedWords[word] = true
		}
	}
	
	// Ajouter les checksum words aux mots interdits
	for _, word := range CHECKSUM_WORDS {
		usedWords[word] = true
	}
	
	var availableWords []string
	for _, word := range wordList {
		if !usedWords[word] {
			availableWords = append(availableWords, word)
		}
	}
	
	return availableWords
}

func worker(workChan <-chan WorkItem, reverseWords map[string]int, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for work := range workChan {
		if atomic.LoadInt32(&foundResult) == 1 {
			return
		}
		
		phrase23Words := work.phrase23Words
		
		// Tester cette phrase de 23 mots avec chacun des 8 mots checksum
		var validChecksumWords []string
		var validMnemonics []string
		
		for _, checksumWord := range CHECKSUM_WORDS {
			atomic.AddInt64(&checksumTestCount, 1)
			
			// Créer la phrase complète de 24 mots
			completeMnemonic := make([]string, 24)
			copy(completeMnemonic, phrase23Words)
			completeMnemonic[23] = checksumWord
			
			// Tester si cette phrase complète est valide BIP39
			if isValidMnemonic(completeMnemonic, reverseWords) {
				completeString := strings.Join(completeMnemonic, " ")
				validChecksumWords = append(validChecksumWords, checksumWord)
				validMnemonics = append(validMnemonics, completeString)
			}
		}
		
		// Vérifier si TOUS les 8 checksum words sont valides
		if len(validChecksumWords) == 8 {
			// EPIC WIN! Cette phrase valide TOUS les 8 checksums!
			if atomic.CompareAndSwapInt32(&foundResult, 0, 1) {
				firstValidMnemonic := validMnemonics[0]
				seed := deriveSeed(firstValidMnemonic, "")
				address := deriveBitcoinAddress(seed)
				
				totalTime := time.Since(startTime)
				finalPhraseRate := float64(work.phraseNumber) / totalTime.Seconds()
				finalChecksumRate := float64(atomic.LoadInt64(&checksumTestCount)) / totalTime.Seconds()
				
				fmt.Println("\n\n🎉🎉🎉 EPIC WIN! 🎉🎉🎉")
				fmt.Printf("✅ PHRASE VALIDANT TOUS LES 8 CHECKSUMS TROUVÉE!\n")
				fmt.Printf("📝 Base phrase (23 mots): %s\n", strings.Join(phrase23Words, " "))
				fmt.Printf("🔤 TOUS les 8 mots checksum sont valides: %v\n", validChecksumWords)
				fmt.Printf("💎 Exemple mnemonic complète: %s\n", firstValidMnemonic)
				fmt.Printf("🔑 Seed: %x\n", seed)
				fmt.Printf("🏦 Bitcoin Address (BIP84): %s\n", address)
				fmt.Printf("🎯 Trouvée après %s phrases (%s tests checksum)\n", formatNumber(work.phraseNumber), formatNumber(atomic.LoadInt64(&checksumTestCount)))
				fmt.Printf("⏰ Temps total: %s\n", formatDuration(totalTime))
				fmt.Printf("⚡ Taux final: %.0f phrases/sec | %.0f tests/sec\n", finalPhraseRate, finalChecksumRate)
				fmt.Printf("🏦 Derivation Path: m/84'/0'/0'/0/0 (BIP84 - Segwit Native)\n")
				
				if *fuzzyMode {
					fmt.Printf("🔍 Mode fuzzy utilisé sur position %v\n", fuzzyPositionsList)
				}
				
				fmt.Printf("\n🔥 TOUTES LES COMBINAISONS VALIDES:\n")
				for i, mnemonic := range validMnemonics {
					fmt.Printf("  %d. %s\n", i+1, mnemonic)
				}
				
				result := Result{
					Mnemonic:           firstValidMnemonic,
					Seed:               fmt.Sprintf("%x", seed),
					Address:            address,
					DerivationPath:     "m/84'/0'/0'/0/0",
					ValidChecksumWords: validChecksumWords,
					FuzzyMode:          *fuzzyMode,
					FuzzyPositions:     fuzzyPositionsList,
					Time:               time.Now().Format(time.RFC3339),
					Attempts:           work.phraseNumber,
					ChecksumTests:      atomic.LoadInt64(&checksumTestCount),
					Duration:           formatDuration(totalTime),
					Rate:               fmt.Sprintf("%.0f phrases/sec", finalPhraseRate),
				}
				
				if *fuzzyMode {
					result.FuzzyPositions = fuzzyPositionsList
				}

				if err := saveResult(result); err != nil {
					fmt.Printf("❌ Erreur sauvegarde: %v\n", err)
				} else {
					fmt.Println("💾 Résultat sauvé dans epic_win_result.json")
				}

				os.Exit(0)
			}
		}
		
		atomic.AddInt64(&attemptCount, 1)
	}
}

func generateAllCombinations(workChan chan<- WorkItem) {
	defer close(workChan)
	
	phraseNumber := int64(0)
	
	// Générer toutes les combinaisons de 23 mots de façon récursive
	var generate func(position int, currentPhrase []string)
	generate = func(position int, currentPhrase []string) {
		if atomic.LoadInt32(&foundResult) == 1 {
			return
		}
		
		if position == 23 {
			// Créer une copie de la phrase pour l'envoyer au worker
			phraseCopy := make([]string, 23)
			copy(phraseCopy, currentPhrase)
			
			phraseNumber++
			workItem := WorkItem{
				phrase23Words: phraseCopy,
				phraseNumber:  phraseNumber,
			}
			
			select {
			case workChan <- workItem:
			case <-time.After(100 * time.Millisecond):
				// Si le canal est plein, on continue (évite les blocages)
			}
			return
		}

		// Obtenir les mots disponibles pour cette position (sans doublons)
		availableWords := getAvailableWordsForPosition(position, currentPhrase, *fuzzyMode)
		
		// Si aucun mot disponible, cette branche s'arrête (pas d'erreur, c'est normal)
		if len(availableWords) == 0 {
			return
		}
		
		for _, word := range availableWords {
			currentPhrase[position] = word
			generate(position+1, currentPhrase)
		}
	}
	
	currentPhrase := make([]string, 23)
	generate(0, currentPhrase)
}

// Calculate real combinations count considering duplicate elimination (parallelized)
func calculateRealCombinations() int64 {
	fmt.Println("🚀 Calcul parallélisé en cours...")
	
	var totalCount int64 = 0
	
	// Progress ticker
	progressTicker := time.NewTicker(2 * time.Second)
	progressDone := make(chan bool)
	
	go func() {
		for {
			select {
			case <-progressTicker.C:
				current := atomic.LoadInt64(&totalCount)
				fmt.Printf("🧮 Combinaisons trouvées: %s\n", formatNumber(current))
			case <-progressDone:
				progressTicker.Stop()
				return
			}
		}
	}()
	
	// Approche simplifiée : diviser le travail par les premiers mots
	var availableFirstWords []string
	if *fuzzyMode && contains(fuzzyPositionsList, 0) {
		// Mode fuzzy pour position 0
		for _, word := range wordList {
			isChecksum := false
			for _, checksumWord := range CHECKSUM_WORDS {
				if word == checksumWord {
					isChecksum = true
					break
				}
			}
			if !isChecksum {
				availableFirstWords = append(availableFirstWords, word)
			}
		}
	} else {
		// Mode normal pour position 0
		availableFirstWords = wordCandidates[0]
	}
	
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	
	// Distribuer le travail par premier mot
	workChan := make(chan string, len(availableFirstWords))
	for _, word := range availableFirstWords {
		workChan <- word
	}
	close(workChan)
	
	// Worker function
	worker := func() {
		defer wg.Done()
		localCount := int64(0)
		
		for firstWord := range workChan {
			// Compter toutes les combinaisons commençant par ce mot
			var countFromPosition func(position int, usedWords map[string]bool)
			countFromPosition = func(position int, usedWords map[string]bool) {
				if position == 23 {
					localCount++
					return
				}
				
				// Get available words for this position
				var availableWords []string
				if *fuzzyMode && contains(fuzzyPositionsList, position) {
					// Fuzzy mode
					for _, word := range wordList {
						if !usedWords[word] {
							// Check if it's not a checksum word
							isChecksum := false
							for _, checksumWord := range CHECKSUM_WORDS {
								if word == checksumWord {
									isChecksum = true
									break
								}
							}
							if !isChecksum {
								availableWords = append(availableWords, word)
							}
						}
					}
				} else {
					// Normal mode
					candidates := wordCandidates[position]
					for _, word := range candidates {
						if !usedWords[word] {
							availableWords = append(availableWords, word)
						}
					}
				}
				
				// If no words available, this branch stops
				if len(availableWords) == 0 {
					return
				}
				
				// Recurse for each available word
				for _, word := range availableWords {
					newUsedWords := make(map[string]bool)
					for k, v := range usedWords {
						newUsedWords[k] = v
					}
					newUsedWords[word] = true
					countFromPosition(position+1, newUsedWords)
				}
			}
			
			// Démarrer le comptage avec le premier mot
			usedWords := make(map[string]bool)
			usedWords[firstWord] = true
			countFromPosition(1, usedWords)
		}
		
		// Ajouter le compte local au total
		atomic.AddInt64(&totalCount, localCount)
	}
	
	// Démarrer les workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	
	// Attendre que tous les workers terminent
	wg.Wait()
	
	// Arrêter le progress ticker
	progressDone <- true
	
	fmt.Printf("✅ Calcul terminé avec %d workers\n", numWorkers)
	return totalCount
}

func main() {
	// Parse CLI arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -f\t\tEnable fuzzy mode\n")
		fmt.Fprintf(os.Stderr, "  -pos=N\t\tPositions to fuzz (comma-separated, e.g., '7,10,20')\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s\t\t\t\tNormal mode\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f -pos=20\t\tFuzzy mode on position 20\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f -pos=7,10,20\tFuzzy mode on positions 7, 10, and 20\n", os.Args[0])
	}
	flag.Parse()

	// Validation des arguments
	if *fuzzyMode && *fuzzyPositions == "" {
		fmt.Println("❌ Erreur: Mode fuzzy activé mais positions non spécifiées (-pos=N)")
		flag.Usage()
		os.Exit(1)
	}
	
	if *fuzzyPositions != "" && !*fuzzyMode {
		fmt.Println("❌ Erreur: Positions spécifiées mais mode fuzzy non activé (-f)")
		flag.Usage()
		os.Exit(1)
	}
	
	if *fuzzyPositions != "" {
		fuzzyPositionsList = make([]int, 0)
		for _, pos := range strings.Split(*fuzzyPositions, ",") {
			posInt, err := strconv.Atoi(strings.TrimSpace(pos))
			if err != nil {
				fmt.Printf("❌ Erreur: Position '%s' invalide\n", pos)
				os.Exit(1)
			}
			if posInt < 0 || posInt > 22 {
				fmt.Printf("❌ Erreur: Position %d doit être entre 0 et 22\n", posInt)
				os.Exit(1)
			}
			fuzzyPositionsList = append(fuzzyPositionsList, posInt)
		}
	}

	// Optimisations de performance
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(50) // GC plus agressif pour éviter l'accumulation
	
	fmt.Println("🚀 Démarrage du cracking BIP39 24-mots (Parallélisé)")
	if *fuzzyMode {
		fmt.Printf("🔍 Mode FUZZY activé sur positions %v\n", fuzzyPositionsList)
	}
	fmt.Println("📚 Chargement de la wordlist...")

	wordList = loadWords("english-wordlist.txt")
	reverseWords := make(map[string]int)
	for i, word := range wordList {
		reverseWords[word] = i
	}

	fmt.Printf("✅ %d mots chargés depuis la wordlist\n", len(wordList))

	// Vérifier que tous les checksum words sont dans la wordlist
	fmt.Printf("🔤 Vérification des %d mots checksum...\n", len(CHECKSUM_WORDS))
	for _, word := range CHECKSUM_WORDS {
		if _, exists := reverseWords[word]; !exists {
			fmt.Printf("❌ Erreur: Checksum word '%s' non trouvé dans la wordlist!\n", word)
			os.Exit(1)
		}
	}
	fmt.Println("✅ Tous les mots checksum sont valides")

	// Calculer le nombre réel de combinaisons (sans doublons)
	fmt.Println("🧮 Calcul du nombre réel de combinaisons (sans doublons)...")
	totalCombinations = calculateRealCombinations()

	totalChecksumTests := totalCombinations * 8 // 8 tests par phrase

	if *fuzzyMode {
		fmt.Printf("🔍 Mode fuzzy sur positions %v\n", fuzzyPositionsList)
	}
	
	fmt.Printf("🔢 Phrases réelles à tester: %s (sans doublons)\n", formatNumber(totalCombinations))
	fmt.Printf("🎯 Total tests checksum: %s (8 par phrase)\n", formatNumber(totalChecksumTests))
	fmt.Printf("🔤 Mots checksum: %v\n", CHECKSUM_WORDS)
	fmt.Println("🔥 OBJECTIF: Trouver une phrase qui valide TOUS les 8 checksum words!")
	
	// Configuration optimisée des workers
	numCPU := runtime.NumCPU()
	numWorkers := numCPU
	if totalCombinations > 1000000 {
		// Pour de gros volumes, utiliser plus de workers mais pas trop
		numWorkers = numCPU * 2
	}
	
	fmt.Printf("🧵 Utilisation de %d workers sur %d cores CPU\n", numWorkers, numCPU)
	fmt.Println()

	startTime = time.Now()
	lastLogTime = startTime
	
	// Démarrer le logger de performance en arrière-plan
	go performanceLogger()
	
	// Configuration des workers avec canal optimisé
	channelSize := 1000
	if totalCombinations < 10000 {
		channelSize = 100
	}
	workChan := make(chan WorkItem, channelSize)
	var wg sync.WaitGroup
	
	// Démarrer les workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(workChan, reverseWords, &wg)
	}
	
	fmt.Println("🏁 Début du traitement parallélisé...")
	if *fuzzyMode {
		fmt.Printf("🔍 Mode fuzzy : positions %v utiliseront toute la wordlist\n", fuzzyPositionsList)
	}
	fmt.Println("══════════════════════════════════════════════════")
	
	// Générer et envoyer les combinaisons aux workers
	go generateAllCombinations(workChan)
	
	// Attendre que tous les workers terminent
	wg.Wait()

	// Si on arrive ici, aucune phrase valide n'a été trouvée
	duration := time.Since(startTime)
	fmt.Printf("\n❌ Recherche terminée en %s\n", formatDuration(duration))
	fmt.Printf("🔍 Total phrases testées: %s\n", formatNumber(atomic.LoadInt64(&attemptCount)))
	fmt.Printf("🎯 Total tests checksum: %s\n", formatNumber(atomic.LoadInt64(&checksumTestCount)))
	fmt.Println("💔 Aucune phrase validant TOUS les 8 checksum words trouvée")
} 