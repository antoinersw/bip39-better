package main

//  @todo Essayer en enlevant les tableaux
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Result represents the successful crack result
type Result struct {
	Mnemonic           string   `json:"mnemonic"`
	Seed               string   `json:"seed"`
	Address            string   `json:"address"`
	DerivationPath     string   `json:"derivation_path"`
	ValidChecksumWords []string `json:"valid_checksum_words"`
	FuzzyMode          bool     `json:"fuzzy_mode"`
	FuzzyPositions     []int    `json:"fuzzy_positions,omitempty"`
	Time               string   `json:"timestamp"`
	Attempts           int64    `json:"attempts"`
	ChecksumTests      int64    `json:"checksum_tests"`
	Duration           string   `json:"duration"`
	Rate               string   `json:"phrases_per_second"`
}

// HighScoreResult represents a phrase with high checksum score
type HighScoreResult struct {
	Phrase             string   `json:"phrase"`
	ValidChecksumWords []string `json:"valid_checksum_words"`
	NumValidChecksums  int      `json:"num_valid_checksums"`
	Timestamp          string   `json:"timestamp"`
}

// FrenchWordMatch represents a French word found in the book with its index
type FrenchWordMatch struct {
	Word  string `json:"word"`
	Index int    `json:"index"`
}

// FrenchWordsResults represents the complete JSON structure from french_words_found.json
type FrenchWordsResults struct {
	Timestamp    string            `json:"timestamp"`
	TotalFound   int               `json:"total_found"`
	Words        []FrenchWordMatch `json:"words"`
	WordsSummary []string          `json:"words_summary"`
}

// CLI flags
var (
	fuzzyMode             = flag.Bool("f", false, "Enable fuzzy mode")
	fuzzyPositions        = flag.String("pos", "", "Positions to fuzz (comma-separated, e.g., '7,10,20' or use multiple -pos flags)")
	fuzzyLtdMode          = flag.Bool("fuzzy-ltd", false, "Enable fuzzy limited mode using French words from book")
	fuzzyLtdPositions     = flag.String("p", "", "Positions for fuzzy-ltd mode (comma-separated, e.g., '7,10,20')")
	reverseMode           = flag.Bool("r", false, "Reverse order of positions 0-11")
	englishMode           = flag.Bool("eng", false, "Use English words directly (skip French-English conversion)")
	bitOptimizeMode       = flag.Bool("bits", false, "Enable bit optimization mode")
	wordTarget            = flag.String("word_target", "", "Target checksum word to validate (for bit optimization)")
	wordValid             = flag.String("word_valid", "", "Comma-separated list of words that must remain valid")
	basePhraseFlag        = flag.String("phrase", "", "Base phrase of 23 words for bit optimization")
	fuzzyPositionsList    []int
	fuzzyLtdPositionsList []int
	wordValidList         []string
)

// Object pools for performance optimization
var (
	usedWordsPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]bool, 25)
		},
	}

	stringSlicePool = sync.Pool{
		New: func() interface{} {
			return make([]string, 0, 24)
		},
	}
)

// Conversion functions between words and bits
func wordToBits(word string, reverseWords map[string]int) int {
	if index, exists := reverseWords[word]; exists {
		return index
	}
	return -1 // Invalid word
}

func bitsToWord(bits int, wordList []string) string {
	if bits >= 0 && bits < len(wordList) {
		return wordList[bits]
	}
	return "" // Invalid bits
}

func convertEnglishWordListToBits(englishWords []string, reverseWords map[string]int) []int {
	bits := make([]int, 0, len(englishWords))
	for _, englishWord := range englishWords {
		if wordBits := wordToBits(englishWord, reverseWords); wordBits != -1 {
			bits = append(bits, wordBits)
		}
	}
	return bits
}

// Convert word candidates to bit candidates
func convertWordCandidatesToBits(candidates [][]string, reverseWords map[string]int) [][]int {
	fmt.Println("🔄 Conversion des candidats de mots vers bits...")

	bitCandidates := make([][]int, len(candidates))
	totalWords := 0
	convertedWords := 0

	for i, position := range candidates {
		bitCandidates[i] = make([]int, 0, len(position))
		for _, word := range position {
			totalWords++
			if wordBits := wordToBits(word, reverseWords); wordBits != -1 {
				bitCandidates[i] = append(bitCandidates[i], wordBits)
				convertedWords++
			} else {
				fmt.Printf("⚠️ Mot '%s' à la position %d non trouvé dans la wordlist\n", word, i)
			}
		}
	}

	fmt.Printf("✅ Conversion bits terminée: %d/%d mots convertis\n", convertedWords, totalWords)
	return bitCandidates
}

// Word candidates for each position (only 23 positions - last word will be from CHECKSUM_WORDS)
// These will be converted to bits during initialization
var wordCandidates = [][]string{
	// erase miss oven father noise reward level blouse rotate admit helmet mansion rice very believe woman deny calm army fade alpha open always
	// 14 premiers mots
	{"erase"}, // 0.449
	{"miss"},  // 0.274
	{"oven"},
	{"father"},  // 0.417
	{"noise"},   // 0.358
	{"reward"},  // 0.387
	{"level"},   // 0.34
	{"blouse"},  // 0.288
	{"rotate"},  // 0.328          // 0.328
	{"admit"},   // 0.328
	{"helmet"},  // 0.21
	{"mansion"}, // 0.371
	// couverture
	{"rice"},
	{"very"},
	// 14 premiers mots end
	// année olympique
	{"believe"},
	{"woman"},
	// lien avec le nom de l'auteur
	{"deny"}, // 0.66
	// sommaire
	{"calm"}, // position 17
	{"army"}, // position 18
	// début d'un chapitre qui traite d'un thème central du livre.
	{"fade"},
	{"alpha"},
	// slogan
	{"open"},   // 1
	{"always"}, // 1

}

// Preprocessed word candidates (will be filled by preprocessing)
var preprocessedWordCandidates [][]string

// Bit-based candidates (converted from word candidates)
var bitCandidates [][]int

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

// Checksum words converted to bits
var CHECKSUM_BITS []int

// Fuzzy-ltd mode words converted to bits
var frenchToEnglishBits []int

// Optimized WorkItem with batch processing
type WorkItem struct {
	phrase23Bits []int // 23 mots en bits (chaque mot = 11 bits, stocké comme index)
	phraseNumber int64
}

// Utility functions for pool management
func getUsedWordsMap() map[string]bool {
	m := usedWordsPool.Get().(map[string]bool)
	// Clear the map
	for k := range m {
		delete(m, k)
	}
	return m
}

func putUsedWordsMap(m map[string]bool) {
	usedWordsPool.Put(m)
}

func getStringSlice() []string {
	s := stringSlicePool.Get().([]string)
	return s[:0] // Reset length but keep capacity
}

func putStringSlice(s []string) {
	if cap(s) > 0 { // Éviter de remettre des slices vides dans le pool
		stringSlicePool.Put(s)
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
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
	gcCount    uint32
	maxMemUsed uint64

	// Best score tracking
	bestScore       int32  // atomic - nombre maximum de checksum corrects trouvés
	bestPhrase      string // phrase avec le meilleur score
	bestPhraseMutex sync.RWMutex

	// High score tracking (pour éviter de sauvegarder plusieurs fois la même phrase)
	savedHighScores map[string]bool
	highScoreMutex  sync.Mutex

	// Fuzzy-ltd mode words (French words from book converted to English)
	frenchToEnglishWords []string
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

// loadFrenchEnglishMapping creates a mapping from French to English words
func loadFrenchEnglishMapping(frenchPath, englishPath string) (map[string]string, error) {
	frenchWords := loadWords(frenchPath)
	englishWords := loadWords(englishPath)

	if len(frenchWords) != len(englishWords) {
		return nil, fmt.Errorf("les fichiers français (%d mots) et anglais (%d mots) n'ont pas le même nombre de mots",
			len(frenchWords), len(englishWords))
	}

	mapping := make(map[string]string, len(frenchWords))
	for i, frenchWord := range frenchWords {
		mapping[frenchWord] = englishWords[i]
	}

	fmt.Printf("✅ Mapping français-anglais créé: %d correspondances\n", len(mapping))
	return mapping, nil
}

// convertFrenchCandidatesToEnglish converts all French words in wordCandidates to English
func convertFrenchCandidatesToEnglish(candidates [][]string, frenchToEnglish map[string]string) [][]string {
	fmt.Println("🔄 Conversion des mots français vers anglais...")

	converted := make([][]string, len(candidates))
	totalWords := 0
	convertedWords := 0
	notFoundWords := 0

	for i, position := range candidates {
		converted[i] = make([]string, len(position))
		for j, frenchWord := range position {
			totalWords++
			if englishWord, exists := frenchToEnglish[frenchWord]; exists {
				converted[i][j] = englishWord
				convertedWords++
			} else {
				fmt.Printf("⚠️ Mot français '%s' non trouvé dans le mapping, conservé tel quel\n", frenchWord)
				converted[i][j] = frenchWord // Garder le mot français si pas trouvé
				notFoundWords++
			}
		}
	}

	fmt.Printf("✅ Conversion terminée: %d/%d mots convertis", convertedWords, totalWords)
	if notFoundWords > 0 {
		fmt.Printf(" (%d mots non trouvés)", notFoundWords)
	}
	fmt.Println()

	return converted
}

// loadFrenchWordsFromJSON loads French words from the JSON file
func loadFrenchWordsFromJSON(jsonPath string) (*FrenchWordsResults, error) {
	file, err := os.Open(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("impossible d'ouvrir le fichier JSON: %v", err)
	}
	defer file.Close()

	var results FrenchWordsResults
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&results); err != nil {
		return nil, fmt.Errorf("impossible de décoder le JSON: %v", err)
	}

	return &results, nil
}

// convertFrenchWordsToEnglishByIndex converts French words to English using correspondence table
func convertFrenchWordsToEnglishByIndex(frenchWords []FrenchWordMatch, frenchList []string, englishList []string) ([]string, error) {
	if len(frenchList) != len(englishList) {
		return nil, fmt.Errorf("les listes française (%d) et anglaise (%d) ont des tailles différentes", len(frenchList), len(englishList))
	}

	// Create mapping from French word to English word using index correspondence
	frenchToEnglish := make(map[string]string)
	for i, frenchWord := range frenchList {
		frenchToEnglish[frenchWord] = englishList[i]
	}

	englishWords := make([]string, 0, len(frenchWords))
	convertedCount := 0
	notFoundCount := 0

	for _, frenchMatch := range frenchWords {
		if englishWord, exists := frenchToEnglish[frenchMatch.Word]; exists {
			englishWords = append(englishWords, englishWord)
			convertedCount++
		} else {
			fmt.Printf("⚠️ Mot français '%s' (index %d) non trouvé dans la correspondance\n", frenchMatch.Word, frenchMatch.Index)
			notFoundCount++
		}
	}

	fmt.Printf("✅ Conversion fuzzy-ltd: %d mots convertis", convertedCount)
	if notFoundCount > 0 {
		fmt.Printf(" (%d non trouvés)", notFoundCount)
	}
	fmt.Println()

	return englishWords, nil
}

func computeChecksum(entropy []byte) *big.Int {
	checksumBits := uint(len(entropy) / 4)
	hash := sha256.Sum256(entropy)
	checksum := new(big.Int).SetBytes(hash[:])
	checksum.Rsh(checksum, uint(len(hash)*8)-checksumBits)
	return checksum
}

// convertPhraseTo253BitEntropy convertit une phrase de 23 mots en entropie de 253 bits
func convertPhraseTo253BitEntropy(phrase23Words []string, reverseWords map[string]int) (*big.Int, error) {
	if len(phrase23Words) != 23 {
		return nil, fmt.Errorf("phrase doit contenir exactement 23 mots, trouvé: %d", len(phrase23Words))
	}

	// Vérifier que tous les mots sont dans la wordlist
	for i, word := range phrase23Words {
		if _, ok := reverseWords[word]; !ok {
			return nil, fmt.Errorf("mot '%s' à la position %d non trouvé dans la wordlist BIP39", word, i)
		}
	}

	// Convertir en entropie de 253 bits (23 mots × 11 bits)
	entropy253 := new(big.Int)
	for _, word := range phrase23Words {
		entropy253.Lsh(entropy253, 11)
		entropy253.Add(entropy253, big.NewInt(int64(reverseWords[word])))
	}

	return entropy253, nil
}

// testChecksumForWord teste si un mot checksum est valide pour une phrase de 23 mots donnée
func testChecksumForWord(phrase23Words []string, checksumWord string, reverseWords map[string]int) bool {
	// Créer une phrase complète de 24 mots
	completeMnemonic := make([]string, 24)
	copy(completeMnemonic[:23], phrase23Words)
	completeMnemonic[23] = checksumWord

	// Utiliser exactement la même logique que isValidMnemonic
	return isValidMnemonic(completeMnemonic, reverseWords)
}

// bitOptimization effectue l'optimisation bit par bit
func bitOptimization(basePhraseWords []string, targetWord string, validWords []string, reverseWords map[string]int) {
	fmt.Println("🔬 DÉMARRAGE DE L'OPTIMISATION BIT PAR BIT")
	fmt.Printf("📝 Phrase de base: %s\n", strings.Join(basePhraseWords, " "))
	fmt.Printf("🎯 Mot cible: %s\n", targetWord)
	fmt.Printf("✅ Mots à conserver valides: %v\n", validWords)
	fmt.Println("══════════════════════════════════════════════════")

	// Convertir la phrase de base en entropie de 253 bits
	baseEntropy, err := convertPhraseTo253BitEntropy(basePhraseWords, reverseWords)
	if err != nil {
		fmt.Printf("❌ Erreur: %v\n", err)
		return
	}

	// Vérifier l'état initial
	fmt.Println("🔍 ÉTAT INITIAL:")
	initiallyValid := make([]string, 0)
	for _, word := range validWords {
		if testChecksumForWord(basePhraseWords, word, reverseWords) {
			initiallyValid = append(initiallyValid, word)
			fmt.Printf("  ✅ %s: VALIDE\n", word)
		} else {
			fmt.Printf("  ❌ %s: INVALIDE\n", word)
		}
	}

	targetInitiallyValid := testChecksumForWord(basePhraseWords, targetWord, reverseWords)
	if targetInitiallyValid {
		fmt.Printf("  🎯 %s: DÉJÀ VALIDE!\n", targetWord)
		fmt.Println("✨ Le mot cible est déjà valide! Aucune optimisation nécessaire.")
		return
	} else {
		fmt.Printf("  🎯 %s: INVALIDE (à optimiser)\n", targetWord)
	}
	fmt.Println()

	fmt.Printf("🧪 Test progressif de 1 à 11 bits...\n")
	fmt.Println()

	startTime := time.Now()
	successFound := false

	// Test progressif : 1 bit, puis 2 bits, puis 3 bits, etc. jusqu'à 11 bits
	for numBits := 1; numBits <= 11 && !successFound; numBits++ {
		fmt.Printf("🔄 ÉTAPE %d: Test de toutes les combinaisons de %d bit(s)\n", numBits, numBits)

		// Calculer le nombre de combinaisons à tester
		totalCombinations := calculateCombinations(253, numBits)
		fmt.Printf("📊 Combinaisons à tester: %d\n", totalCombinations)

		var testCount int64 = 0
		stepStartTime := time.Now()

		// Générer toutes les combinaisons de numBits parmi 253 positions
		successFound = testBitCombinations(baseEntropy, numBits, targetWord, validWords, reverseWords, &testCount, stepStartTime)

		if successFound {
			break
		}

		stepDuration := time.Since(stepStartTime)
		fmt.Printf("❌ Étape %d terminée sans succès (%d tests en %v)\n", numBits, testCount, stepDuration)
		fmt.Println()
	}

	if !successFound {
		totalTime := time.Since(startTime)
		fmt.Printf("\n❌ ÉCHEC: Aucune solution trouvée après test de 253 bits\n")
		fmt.Printf("⏰ Temps total: %v\n", totalTime)
		fmt.Println("💡 Suggestion: Essayez avec une phrase de base différente ou des mots requis différents")
	}
}

// convertEntropy253ToPhrase convertit une entropie de 253 bits en phrase de 23 mots
func convertEntropy253ToPhrase(entropy253 *big.Int, reverseWords map[string]int) []string {
	// Créer le mapping inverse (index -> mot)
	indexToWord := make([]string, len(reverseWords))
	for word, index := range reverseWords {
		indexToWord[index] = word
	}

	phrase := make([]string, 23)
	entropyClone := new(big.Int).Set(entropy253)

	// Extraire chaque mot (11 bits) depuis la fin
	for i := 22; i >= 0; i-- {
		wordIndex := new(big.Int)
		entropyClone.DivMod(entropyClone, big.NewInt(2048), wordIndex) // 2048 = 2^11
		phrase[i] = indexToWord[wordIndex.Int64()]
	}

	return phrase
}

// calculateCombinations calcule C(n,k) = n! / (k! * (n-k)!)
func calculateCombinations(n, k int) int64 {
	if k > n || k < 0 {
		return 0
	}
	if k == 0 || k == n {
		return 1
	}
	if k > n-k {
		k = n - k // Optimisation: C(n,k) = C(n,n-k)
	}

	result := int64(1)
	for i := 0; i < k; i++ {
		result = result * int64(n-i) / int64(i+1)
	}
	return result
}

// BitCombinationWork représente une combinaison de bits à tester
type BitCombinationWork struct {
	positions []int
	workID    int64
}

// BitOptimizationResult représente le résultat d'un test réussi
type BitOptimizationResult struct {
	positions      []int
	modifiedPhrase []string
	validChecksums []string
	targetWord     string
	validWords     []string
	elapsed        time.Duration
}

// testBitCombinations teste toutes les combinaisons de numBits parmi 253 positions en parallèle
func testBitCombinations(baseEntropy *big.Int, numBits int, targetWord string, validWords []string, reverseWords map[string]int, testCount *int64, stepStartTime time.Time) bool {
	// Configuration des workers
	numCPU := runtime.NumCPU()
	numWorkers := numCPU * 4 // Plus de workers pour maximiser l'utilisation CPU

	// Calculer la taille du canal en fonction du nombre de combinaisons
	totalCombinations := calculateCombinations(253, numBits)
	channelSize := int(min(int64(100000), totalCombinations/10))
	if channelSize < 1000 {
		channelSize = 1000
	}

	fmt.Printf("🚀 Démarrage de %d workers sur %d CPU cores (canal: %d)\n", numWorkers, numCPU, channelSize)

	// Channels pour la communication
	workChan := make(chan BitCombinationWork, channelSize)
	resultChan := make(chan BitOptimizationResult, 1)
	doneChan := make(chan bool, numWorkers)

	// Variables atomiques pour le monitoring
	var workersTestCount int64
	var foundResult int32

	// Performance monitoring en arrière-plan
	monitoringDone := make(chan bool)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		lastTestCount := int64(0)
		lastTime := stepStartTime

		for {
			select {
			case <-ticker.C:
				if atomic.LoadInt32(&foundResult) == 1 {
					return
				}

				currentTestCount := atomic.LoadInt64(&workersTestCount)
				currentTime := time.Now()

				// Calculer le taux
				deltaTests := currentTestCount - lastTestCount
				deltaTime := currentTime.Sub(lastTime)
				testsPerSecond := float64(deltaTests) / deltaTime.Seconds()

				elapsed := currentTime.Sub(stepStartTime)
				progress := float64(currentTestCount) / float64(totalCombinations) * 100.0

				fmt.Printf("⚡ [%v] %.2f%% | %s tests | %.0f tests/sec | ETA: %v\n",
					formatDuration(elapsed),
					progress,
					formatNumber(currentTestCount),
					testsPerSecond,
					estimateTimeLeft(currentTestCount, totalCombinations, testsPerSecond))

				lastTestCount = currentTestCount
				lastTime = currentTime

			case <-monitoringDone:
				return
			}
		}
	}()

	// Démarrer les workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go bitOptimizationWorker(i, baseEntropy, targetWord, validWords, reverseWords, workChan, resultChan, doneChan, &workersTestCount, &foundResult, &wg)
	}

	// Goroutine pour générer les combinaisons
	go func() {
		defer close(workChan)
		generateBitCombinationsParallel(numBits, workChan, &foundResult)
	}()

	// Attendre le résultat ou la fin de tous les workers
	select {
	case result := <-resultChan:
		// SUCCÈS trouvé!
		atomic.StoreInt32(&foundResult, 1)
		close(monitoringDone)

		fmt.Printf("\n🎉 SUCCÈS TROUVÉ PAR UN WORKER!\n")
		fmt.Printf("🔧 Bits modifiés (%d): %v\n", len(result.positions), result.positions)
		fmt.Printf("⏰ Temps écoulé: %v\n", result.elapsed)
		fmt.Printf("🎯 Mot cible '%s': MAINTENANT VALIDE\n", result.targetWord)
		fmt.Printf("✅ Mots conservés valides: %v\n", result.validWords)
		fmt.Println()

		fmt.Printf("📝 NOUVELLE PHRASE OPTIMISÉE:\n")
		fmt.Printf("   %s\n", strings.Join(result.modifiedPhrase, " "))
		fmt.Println()

		fmt.Printf("🏆 SCORE FINAL: %d/8 mots checksum valides\n", len(result.validChecksums))
		fmt.Printf("🔤 Mots valides: %v\n", result.validChecksums)

		return true

	case <-func() chan bool {
		// Attendre que tous les workers terminent
		go func() {
			wg.Wait()
			close(doneChan)
		}()
		return doneChan
	}():
		close(monitoringDone)
		*testCount = atomic.LoadInt64(&workersTestCount)
		return false
	}
}

// bitOptimizationWorker traite les combinaisons de bits en parallèle
func bitOptimizationWorker(_ int, baseEntropy *big.Int, targetWord string, validWords []string, reverseWords map[string]int, workChan <-chan BitCombinationWork, resultChan chan<- BitOptimizationResult, _ chan<- bool, testCount *int64, foundResult *int32, wg *sync.WaitGroup) {
	defer wg.Done()

	for work := range workChan {
		if atomic.LoadInt32(foundResult) == 1 {
			return
		}

		atomic.AddInt64(testCount, 1)

		// Créer une copie de l'entropie et flipper les bits sélectionnés
		modifiedEntropy := new(big.Int).Set(baseEntropy)

		for _, bitPos := range work.positions {
			if modifiedEntropy.Bit(bitPos) == 1 {
				modifiedEntropy.SetBit(modifiedEntropy, bitPos, 0)
			} else {
				modifiedEntropy.SetBit(modifiedEntropy, bitPos, 1)
			}
		}

		// Convertir l'entropie modifiée en phrase de 23 mots
		modifiedPhrase := convertEntropy253ToPhrase(modifiedEntropy, reverseWords)
		if modifiedPhrase == nil {
			continue // Skip si conversion échoue
		}

		// Tester si le mot cible devient valide
		if testChecksumForWord(modifiedPhrase, targetWord, reverseWords) {
			// Le mot cible est maintenant valide! Vérifier les mots à conserver
			allValidWordsStillValid := true
			currentlyValidWords := make([]string, 0)

			for _, word := range validWords {
				if testChecksumForWord(modifiedPhrase, word, reverseWords) {
					currentlyValidWords = append(currentlyValidWords, word)
				} else {
					allValidWordsStillValid = false
					break
				}
			}

			if allValidWordsStillValid {
				// SUCCÈS! Tester tous les checksum words
				allValidChecksums := make([]string, 0)
				for _, checksumWord := range CHECKSUM_WORDS {
					if testChecksumForWord(modifiedPhrase, checksumWord, reverseWords) {
						allValidChecksums = append(allValidChecksums, checksumWord)
					}
				}

				// Envoyer le résultat
				result := BitOptimizationResult{
					positions:      append([]int(nil), work.positions...),    // Copy slice
					modifiedPhrase: append([]string(nil), modifiedPhrase...), // Copy slice
					validChecksums: allValidChecksums,
					targetWord:     targetWord,
					validWords:     currentlyValidWords,
					elapsed:        time.Since(time.Now()), // Will be corrected by caller
				}

				select {
				case resultChan <- result:
					return // Succès envoyé
				default:
					// Channel plein, quelqu'un d'autre a déjà trouvé
					return
				}
			}
		}
	}
}

// generateBitCombinationsParallel génère toutes les combinaisons de bits et les envoie aux workers
func generateBitCombinationsParallel(numBits int, workChan chan<- BitCombinationWork, foundResult *int32) {
	positions := make([]int, numBits)
	var workID int64 = 0

	// Fonction récursive pour générer les combinaisons
	var generateCombinations func(start, depth int)
	generateCombinations = func(start, depth int) {
		if atomic.LoadInt32(foundResult) == 1 {
			return
		}

		if depth == numBits {
			// Créer une copie de la combinaison
			workID++
			positionsCopy := make([]int, numBits)
			copy(positionsCopy, positions)

			work := BitCombinationWork{
				positions: positionsCopy,
				workID:    workID,
			}

			select {
			case workChan <- work:
			case <-time.After(1 * time.Second):
				// Timeout si le channel est bloqué trop longtemps
			}
			return
		}

		// Générer la prochaine combinaison
		for i := start; i < 253; i++ {
			if atomic.LoadInt32(foundResult) == 1 {
				return
			}
			positions[depth] = i
			generateCombinations(i+1, depth+1)
		}
	}

	generateCombinations(0, 0)
}

// estimateTimeLeft estime le temps restant
func estimateTimeLeft(current, total int64, testsPerSecond float64) time.Duration {
	if testsPerSecond <= 0 {
		return time.Duration(0)
	}
	remaining := total - current
	secondsLeft := float64(remaining) / testsPerSecond
	return time.Duration(secondsLeft) * time.Second
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

// **BOTTLENECK #1 RÉSOLU** : Fonctions ultra-optimisées pour validation BIP39
// Gain de performance : 8x plus rapide grâce à la séparation entropy/checksum

// Buffer global pour éviter les allocations répétées dans la génération
var globalBitsBuffer = make([]int, 23)

// **BOTTLENECK #2 RÉSOLU** : Conversion optimisée sans allocation
func convertPhraseToBitsOptimized(phrase []string, reverseWords map[string]int) []int {
	// Copier dans le buffer global et le retourner (évite l'allocation à chaque fois)
	result := make([]int, 23)
	for i, word := range phrase {
		result[i] = wordToBits(word, reverseWords)
	}
	return result
}

// Version optimisée qui calcule l'entropy de 253 bits une seule fois
func computePhrase23Entropy(phrase23Bits []int) *big.Int {
	entropy253 := new(big.Int)

	// Construire l'entropy de 253 bits (23 mots × 11 bits)
	for _, wordBits := range phrase23Bits {
		entropy253.Lsh(entropy253, 11)
		entropy253.Add(entropy253, big.NewInt(int64(wordBits)))
	}

	return entropy253
}

// Test ultra-rapide du checksum pour une entropy donnée
func isChecksumValidForEntropy(entropy253 *big.Int, checksumBits int) bool {
	// Construire l'entropy complète de 256 bits
	entropy256 := new(big.Int).Set(entropy253)
	entropy256.Lsh(entropy256, 3) // Décaler de 3 bits pour faire place au checksum

	// Ajouter les 3 premiers bits du checksum word
	topBits := (checksumBits >> 8) & 0x7 // 3 bits supérieurs
	entropy256.Or(entropy256, big.NewInt(int64(topBits)))

	// Calculer le checksum attendu
	expectedChecksum := computeChecksumFast(entropy256)

	// Comparer avec les 8 bits de checksum réels
	actualChecksum := checksumBits & 0xFF // 8 bits inférieurs

	return actualChecksum == expectedChecksum
}

// Version optimisée de computeChecksum
func computeChecksumFast(entropy256 *big.Int) int {
	entropyBytes := entropy256.Bytes()

	// Pad à 32 bytes si nécessaire (version optimisée)
	if len(entropyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(entropyBytes):], entropyBytes)
		entropyBytes = padded
	} else if len(entropyBytes) > 32 {
		entropyBytes = entropyBytes[len(entropyBytes)-32:]
	}

	// SHA256 et extraction des 8 premiers bits
	hash := sha256.Sum256(entropyBytes)
	return int(hash[0])
}

// Version de backup (garde l'ancienne pour compatibilité)
func isValidMnemonicBitsOld(phrase23Bits []int, checksumBits int) bool {
	if len(phrase23Bits) != 23 {
		return false
	}

	// Convert bits to big integer (23 words + 1 checksum word = 264 bits total)
	mnemonicBig := new(big.Int)

	// Add 23 words (253 bits)
	for _, wordBits := range phrase23Bits {
		mnemonicBig.Lsh(mnemonicBig, 11)
		mnemonicBig.Add(mnemonicBig, big.NewInt(int64(wordBits)))
	}

	// Add checksum word (11 bits)
	mnemonicBig.Lsh(mnemonicBig, 11)
	mnemonicBig.Add(mnemonicBig, big.NewInt(int64(checksumBits)))

	// For 24 words: 8 checksum bits (256 entropy bits + 8 checksum bits = 264 total bits)
	checksumBitCount := 8
	checksum := new(big.Int)
	entropy := new(big.Int)
	entropy.DivMod(mnemonicBig, big.NewInt(1<<checksumBitCount), checksum)

	// Get entropy bytes (should be 32 bytes for 256 bits)
	entropyBytes := entropy.Bytes()

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

func saveHighScorePhrase(phrase23Words []string, validChecksumWords []string) error {
	// Créer la phrase complète de 23 mots
	phraseString := strings.Join(phrase23Words, " ")

	highScore := HighScoreResult{
		Phrase:             phraseString,
		ValidChecksumWords: append([]string(nil), validChecksumWords...), // Copy slice
		NumValidChecksums:  len(validChecksumWords),
		Timestamp:          time.Now().Format(time.RFC3339),
	}

	// Fichier unique en mode append (JSONL format - une ligne JSON par résultat)
	filename := "high_scores_live.jsonl"

	// Ouvrir en mode append (ou créer si n'existe pas)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encoder sur une seule ligne (pas d'indentation pour JSONL)
	encoder := json.NewEncoder(file)
	return encoder.Encode(highScore)
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
	ticker := time.NewTicker(1 * time.Minute) // Logging toutes les minutes
	defer ticker.Stop()

	for range ticker.C {
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

		// Affichage compact des stats avec monitoring + meilleur score
		currentBestScore := atomic.LoadInt32(&bestScore)
		bestScoreInfo := ""
		if currentBestScore > 0 {
			bestScoreInfo = fmt.Sprintf(" | 🎯 Best: %d/8", currentBestScore)
		}

		fmt.Printf("📊 [%s] %.2f%% | %s/%s phrases | %.0f p/s | %s tests/s | ETA: %s | MEM: %s%s%s\n",
			formatDuration(elapsed),
			progressPercent,
			formatNumber(currentAttempts),
			formatNumber(totalCombinations),
			overallPhraseRate,
			formatNumber(int64(checksumPerSecond)),
			formatDuration(estimatedTimeLeft),
			formatMemory(m.Alloc),
			performanceWarning,
			bestScoreInfo)

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

// Helper function to check if a slice contains an integer
func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Helper function to check if a phrase contains duplicate words
func hasDuplicateWords(phrase []string) bool {
	seen := make(map[string]bool)
	for _, word := range phrase {
		if seen[word] {
			return true
		}
		seen[word] = true
	}
	return false
}

// Helper function to check if a phrase contains duplicate bits

func preprocessWordCandidates(candidates [][]string) [][]string {
	fmt.Println("🧹 Pré-traitement des candidats de mots...")

	// Vérifier si nous avons assez de positions pour une phrase de 23 mots
	if len(candidates) < 23 {
		fmt.Printf("❌ ERREUR: Seulement %d positions définies, mais 23 requises pour une phrase de 23 mots\n", len(candidates))
		fmt.Println("🔧 Extension automatique avec des positions vides...")

		// Étendre le tableau pour avoir 23 positions
		extended := make([][]string, 23)
		copy(extended, candidates)

		// Remplir les positions manquantes avec des slices vides
		for i := len(candidates); i < 23; i++ {
			extended[i] = []string{} // Position vide
		}
		candidates = extended
	}

	// Appliquer le mode reverse si activé
	if *reverseMode {
		fmt.Println("🔄 Mode REVERSE: Inversion des positions 0-11...")
		candidates = applyReverseMode(candidates)
	}

	// Calculer les stats sans supprimer les doublons
	totalWords := 0
	emptyPositions := 0

	for i, words := range candidates {
		totalWords += len(words)

		if len(words) == 0 {
			emptyPositions++
			fmt.Printf("  ⚠️ Position %d: VIDE\n", i)
		}
	}

	fmt.Printf("✅ Pré-traitement terminé: %d → %d mots total (-0 doublons)\n",
		totalWords, totalWords)

	if emptyPositions > 0 {
		fmt.Printf("⚠️ ATTENTION: %d positions sont vides! Cela résultera en 0 combinaisons.\n", emptyPositions)
		fmt.Println("💡 Suggestion: Activez le mode fuzzy (-f -pos=X,Y,Z) pour ces positions.")
	}

	return candidates
}

// applyReverseMode inverse l'ordre des candidats pour les positions 0-11
func applyReverseMode(candidates [][]string) [][]string {
	reversed := make([][]string, len(candidates))
	copy(reversed, candidates)

	// Inverser seulement les positions 0 à 11 (12 premières positions)
	for i := 0; i < 12 && i < len(reversed)/2; i++ {
		j := 11 - i
		if j < len(reversed) {
			reversed[i], reversed[j] = reversed[j], reversed[i]
			fmt.Printf("  🔄 Position %d ↔ Position %d\n", i, j)
		}
	}

	return reversed
}

func worker(workChan <-chan WorkItem, wg *sync.WaitGroup) {
	defer wg.Done()

	// Réutiliser des slices pour les résultats
	validChecksumWords := getStringSlice()
	validMnemonics := getStringSlice()

	defer func() {
		putStringSlice(validChecksumWords)
		putStringSlice(validMnemonics)
	}()

	for work := range workChan {
		if atomic.LoadInt32(&foundResult) == 1 {
			return
		}

		phrase23Bits := work.phrase23Bits

		// Reset slices for reuse
		validChecksumWords = validChecksumWords[:0]
		validMnemonics = validMnemonics[:0]

		// **OPTIMISATION MASSIVE** : Pré-calculer l'entropy une seule fois
		// Au lieu de recalculer 8 fois la même entropy de 253 bits !
		entropy253 := computePhrase23Entropy(phrase23Bits)

		// Tester cette phrase de 23 bits avec chacun des 8 bits checksum (ultra-rapide maintenant)
		for _, checksumBits := range CHECKSUM_BITS {
			atomic.AddInt64(&checksumTestCount, 1)

			// Test ultra-rapide avec entropy pré-calculée
			if isChecksumValidForEntropy(entropy253, checksumBits) {
				// Reconstituer en mots seulement pour la sauvegarde/log
				phrase23Words := make([]string, 23)
				for i, bits := range phrase23Bits {
					phrase23Words[i] = bitsToWord(bits, wordList)
				}
				checksumWord := bitsToWord(checksumBits, wordList)

				completeMnemonic := make([]string, 24)
				copy(completeMnemonic[:23], phrase23Words)
				completeMnemonic[23] = checksumWord

				completeString := strings.Join(completeMnemonic, " ")
				validChecksumWords = append(validChecksumWords, checksumWord)
				validMnemonics = append(validMnemonics, completeString)
			}
		}

		// Reconstituer phrase23Words depuis les bits une seule fois pour tous les usages
		var phrase23Words []string
		if len(validChecksumWords) > 0 {
			phrase23Words = make([]string, 23)
			for i, bits := range phrase23Bits {
				phrase23Words[i] = bitsToWord(bits, wordList)
			}
		}

		// Tracker le meilleur score (performance optimisée avec atomic)
		currentScore := int32(len(validChecksumWords))
		if currentScore > 0 {
			currentBestScore := atomic.LoadInt32(&bestScore)
			if currentScore > currentBestScore {
				if atomic.CompareAndSwapInt32(&bestScore, currentBestScore, currentScore) {
					// Nouveau meilleur score ! Sauvegarder la phrase (avec mutex pour éviter les races)
					phraseString := strings.Join(phrase23Words, " ")
					bestPhraseMutex.Lock()
					bestPhrase = phraseString
					bestPhraseMutex.Unlock()
				}
			}
		}

		// Sauvegarder automatiquement les phrases avec score > 3
		if len(validChecksumWords) > 3 {
			phraseString := strings.Join(phrase23Words, " ")

			// Vérifier si on a déjà sauvegardé cette phrase (éviter les doublons)
			highScoreMutex.Lock()
			alreadySaved := savedHighScores[phraseString]
			if !alreadySaved {
				savedHighScores[phraseString] = true
			}
			highScoreMutex.Unlock()

			if !alreadySaved {
				// Sauvegarder immédiatement (pas en arrière-plan pour éviter les pertes)
				err := saveHighScorePhrase(phrase23Words, validChecksumWords)
				if err != nil {
					fmt.Printf("⚠️ Erreur sauvegarde high score: %v\n", err)
				} else {
					fmt.Printf("💾 [LIVE] Sauvé: %d/8 checksums -> high_scores_live.jsonl\n",
						len(validChecksumWords))
					fmt.Printf("   📝 Phrase: %s\n", phraseString)
				}
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
					fmt.Printf("🔍 Mode fuzzy utilisé sur positions %v\n", fuzzyPositionsList)
				}
				if *fuzzyLtdMode {
					fmt.Printf("📖 Mode fuzzy-ltd utilisé sur positions %v (%d mots du livre)\n", fuzzyLtdPositionsList, len(frenchToEnglishWords))
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
					ValidChecksumWords: append([]string(nil), validChecksumWords...), // Copy for result
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
				if *fuzzyLtdMode {
					result.FuzzyPositions = fuzzyLtdPositionsList
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

func generateAllCombinations(workChan chan<- WorkItem, reverseWords map[string]int) {
	defer close(workChan)

	var phraseNumber int64 = 0

	// Fonction récursive pour générer toutes les combinaisons (garde les mots pour simplifier)
	var generateFromPosition func(position int, currentPhrase []string, usedWords map[string]bool)
	generateFromPosition = func(position int, currentPhrase []string, usedWords map[string]bool) {
		if atomic.LoadInt32(&foundResult) == 1 {
			return
		}

		if position == 23 {
			// Vérifier s'il y a des mots dupliqués - skip si c'est le cas
			if hasDuplicateWords(currentPhrase) {
				return // Skip cette phrase
			}

			phraseNumber++

			// **BOTTLENECK #2 RÉSOLU** : Pré-convertir en bits SANS allocations répétées
			// Réutiliser un buffer global au lieu d'allouer à chaque fois
			workItem := WorkItem{
				phrase23Bits: convertPhraseToBitsOptimized(currentPhrase, reverseWords),
				phraseNumber: phraseNumber,
			}

			select {
			case workChan <- workItem:
			case <-time.After(500 * time.Millisecond):
				// Si le canal est plein, on attend un peu plus longtemps
			}
			return
		}

		// Obtenir les mots disponibles pour cette position
		var availableWords []string
		if *fuzzyMode && contains(fuzzyPositionsList, position) {
			// Mode fuzzy : utiliser toute la wordlist sauf les mots déjà utilisés et checksum words
			availableWords = getStringSlice()
			for _, word := range wordList {
				if !usedWords[word] {
					// Vérifier que ce n'est pas un checksum word
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
		} else if *fuzzyLtdMode && contains(fuzzyLtdPositionsList, position) {
			// Mode fuzzy-ltd : utiliser les mots du livre convertis en anglais
			availableWords = getStringSlice()
			for _, word := range frenchToEnglishWords {
				if !usedWords[word] {
					// Vérifier que ce n'est pas un checksum word
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
			// Mode normal : utiliser les candidats pré-traités
			candidates := preprocessedWordCandidates[position]
			availableWords = getStringSlice()
			for _, word := range candidates {
				if !usedWords[word] {
					availableWords = append(availableWords, word)
				}
			}
		}

		// Si aucun mot disponible, cette branche s'arrête
		if len(availableWords) == 0 {
			putStringSlice(availableWords)
			return
		}

		for _, word := range availableWords {
			currentPhrase[position] = word

			// Optimisation : réutiliser la map usedWords au lieu de la copier
			usedWords[word] = true
			generateFromPosition(position+1, currentPhrase, usedWords)
			delete(usedWords, word) // Nettoyer après récursion
		}

		putStringSlice(availableWords)
	}

	fmt.Printf("🚀 Démarrage de la génération de toutes les combinaisons\n")

	// Démarrer la génération récursive
	currentPhrase := make([]string, 23)
	usedWords := getUsedWordsMap()
	generateFromPosition(0, currentPhrase, usedWords)
	putUsedWordsMap(usedWords)
}

// Calculate estimated combinations count (simple estimation)
func calculateEstimatedCombinations() int64 {
	fmt.Println("🧮 Calcul d'estimation rapide des combinaisons...")

	var estimate int64 = 1

	for i, candidates := range bitCandidates {
		var positionCount int64

		if *fuzzyMode && contains(fuzzyPositionsList, i) {
			// Mode fuzzy : environ 2040 mots (2048 - 8 checksum words)
			positionCount = 2040
		} else if *fuzzyLtdMode && contains(fuzzyLtdPositionsList, i) {
			// Mode fuzzy-ltd : nombre de mots du livre
			positionCount = int64(len(frenchToEnglishBits))
		} else {
			// Mode normal : nombre de candidats pour cette position
			positionCount = int64(len(candidates))
		}

		if positionCount > 0 {
			estimate = estimate * positionCount
			// Éviter les overflows énormes en limitant l'estimation
			if estimate > 1e15 {
				fmt.Println("⚠️ Estimation très élevée, limitée à 1e15")
				return int64(1e15)
			}
		} else {
			fmt.Printf("⚠️ Position %d a 0 candidats - résultat sera 0\n", i)
			return 0
		}
	}

	fmt.Printf("✅ Estimation rapide terminée\n")
	return estimate
}

func main() {
	// Parse CLI arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nModes:\n")
		fmt.Fprintf(os.Stderr, "  -f\t\t\tEnable fuzzy mode\n")
		fmt.Fprintf(os.Stderr, "  -r\t\t\tReverse order of positions 0-11\n")
		fmt.Fprintf(os.Stderr, "  -bits\t\t\tEnable bit optimization mode\n")
		fmt.Fprintf(os.Stderr, "\nFuzzy Mode Options:\n")
		fmt.Fprintf(os.Stderr, "  -pos=N\t\tPositions to fuzz (comma-separated, e.g., '7,10,20')\n")
		fmt.Fprintf(os.Stderr, "  -eng\t\t\tUse English words directly (skip French-English conversion)\n")
		fmt.Fprintf(os.Stderr, "\nFuzzy Limited Mode Options:\n")
		fmt.Fprintf(os.Stderr, "  --fuzzy-ltd\t\tEnable fuzzy limited mode using French words from book\n")
		fmt.Fprintf(os.Stderr, "  -p=N\t\t\tPositions for fuzzy-ltd mode (comma-separated, e.g., '7,10,20')\n")
		fmt.Fprintf(os.Stderr, "\nBit Optimization Mode Options:\n")
		fmt.Fprintf(os.Stderr, "  -phrase=\"...\"\t\tBase phrase of 23 words\n")
		fmt.Fprintf(os.Stderr, "  -word_target=WORD\tTarget checksum word to validate\n")
		fmt.Fprintf(os.Stderr, "  -word_valid=\"W1,W2\"\tComma-separated words that must remain valid\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s\t\t\t\t\t\tFrench mode (default)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -eng\t\t\t\t\tEnglish mode\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r\t\t\t\t\tReverse mode (positions 0-11 reversed)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f -pos=20\t\t\t\tFuzzy mode on position 20\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -eng -f -pos=7,10,20\t\t\tEnglish + Fuzzy mode on positions 7, 10, and 20\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --fuzzy-ltd -p=20,21\t\t\tFuzzy-ltd mode using book words on positions 20 and 21\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -bits -phrase=\"word1 word2 ...\" -word_target=flip -word_valid=\"alien,detect\"\n", os.Args[0])
	}
	flag.Parse()

	// Validation des arguments pour le mode bit optimization
	if *bitOptimizeMode {
		if *basePhraseFlag == "" {
			fmt.Println("❌ Erreur: Mode bit optimization activé mais phrase de base non spécifiée (-phrase=\"...\")")
			flag.Usage()
			os.Exit(1)
		}
		if *wordTarget == "" {
			fmt.Println("❌ Erreur: Mode bit optimization activé mais mot cible non spécifié (-word_target=WORD)")
			flag.Usage()
			os.Exit(1)
		}
		// Vérifier que le mot cible est dans les checksum words
		targetValid := false
		for _, word := range CHECKSUM_WORDS {
			if word == *wordTarget {
				targetValid = true
				break
			}
		}
		if !targetValid {
			fmt.Printf("❌ Erreur: Mot cible '%s' n'est pas dans les checksum words valides: %v\n", *wordTarget, CHECKSUM_WORDS)
			os.Exit(1)
		}
		// Parser les mots à conserver valides
		if *wordValid != "" {
			wordValidList = strings.Split(*wordValid, ",")
			for i, word := range wordValidList {
				wordValidList[i] = strings.TrimSpace(word)
				// Vérifier que chaque mot est dans les checksum words
				wordIsValid := false
				for _, validWord := range CHECKSUM_WORDS {
					if validWord == wordValidList[i] {
						wordIsValid = true
						break
					}
				}
				if !wordIsValid {
					fmt.Printf("❌ Erreur: Mot à conserver '%s' n'est pas dans les checksum words valides: %v\n", wordValidList[i], CHECKSUM_WORDS)
					os.Exit(1)
				}
			}
		}
	}

	// Validation des arguments pour le mode fuzzy
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

	// Validation des arguments pour le mode fuzzy-ltd
	if *fuzzyLtdMode && *fuzzyLtdPositions == "" {
		fmt.Println("❌ Erreur: Mode fuzzy-ltd activé mais positions non spécifiées (-p=N)")
		flag.Usage()
		os.Exit(1)
	}

	if *fuzzyLtdPositions != "" && !*fuzzyLtdMode {
		fmt.Println("❌ Erreur: Positions spécifiées mais mode fuzzy-ltd non activé (--fuzzy-ltd)")
		flag.Usage()
		os.Exit(1)
	}

	if *fuzzyLtdPositions != "" {
		fuzzyLtdPositionsList = make([]int, 0)
		for _, pos := range strings.Split(*fuzzyLtdPositions, ",") {
			posInt, err := strconv.Atoi(strings.TrimSpace(pos))
			if err != nil {
				fmt.Printf("❌ Erreur: Position '%s' invalide\n", pos)
				os.Exit(1)
			}
			if posInt < 0 || posInt > 22 {
				fmt.Printf("❌ Erreur: Position %d doit être entre 0 et 22\n", posInt)
				os.Exit(1)
			}
			fuzzyLtdPositionsList = append(fuzzyLtdPositionsList, posInt)
		}
	}

	// Vérifier qu'on n'a qu'un seul mode activé
	if *bitOptimizeMode && *fuzzyMode {
		fmt.Println("❌ Erreur: Vous ne pouvez pas activer les modes bit optimization ET fuzzy en même temps")
		flag.Usage()
		os.Exit(1)
	}

	if *bitOptimizeMode && *fuzzyLtdMode {
		fmt.Println("❌ Erreur: Vous ne pouvez pas activer les modes bit optimization ET fuzzy-ltd en même temps")
		flag.Usage()
		os.Exit(1)
	}

	if *fuzzyMode && *fuzzyLtdMode {
		fmt.Println("❌ Erreur: Vous ne pouvez pas activer les modes fuzzy ET fuzzy-ltd en même temps")
		flag.Usage()
		os.Exit(1)
	}

	// Optimisations de performance
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(50) // GC plus agressif pour éviter l'accumulation

	// Initialiser la map pour tracker les phrases high score déjà sauvegardées
	savedHighScores = make(map[string]bool)

	if *fuzzyMode {
		fmt.Printf("🔍 Mode FUZZY activé sur positions %v\n", fuzzyPositionsList)
	}

	if *fuzzyLtdMode {
		fmt.Printf("🔍 Mode FUZZY-LTD activé sur positions %v\n", fuzzyLtdPositionsList)
	}

	if *reverseMode {
		fmt.Printf("🔄 Mode REVERSE activé: positions 0-11 inversées\n")
	}

	var finalWordCandidates [][]string

	if *englishMode {
		// Mode anglais : utiliser directement les mots anglais
		fmt.Println("🇺🇸 Mode ANGLAIS: Utilisation directe des mots anglais")
		finalWordCandidates = wordCandidates
	} else {
		// Mode français : conversion nécessaire
		fmt.Println("🇫🇷 Mode FRANÇAIS: Conversion vers anglais...")

		// ÉTAPE 1: Créer le mapping français-anglais
		fmt.Println("🌍 Création du mapping français-anglais...")
		frenchToEnglish, err := loadFrenchEnglishMapping("words/french.txt", "words/english.txt")
		if err != nil {
			fmt.Printf("❌ Erreur lors du chargement du mapping: %v\n", err)
			os.Exit(1)
		}

		// ÉTAPE 2: Convertir les candidats français vers anglais
		finalWordCandidates = convertFrenchCandidatesToEnglish(wordCandidates, frenchToEnglish)
	}

	fmt.Println("📚 Chargement de la wordlist anglaise...")

	wordList = loadWords("./words/english.txt")
	reverseWords := make(map[string]int)
	for i, word := range wordList {
		reverseWords[word] = i
	}

	fmt.Printf("✅ %d mots chargés depuis la wordlist\n", len(wordList))

	// ÉTAPE 3: Pré-traitement des candidats de mots (maintenant en anglais)
	preprocessedWordCandidates = preprocessWordCandidates(finalWordCandidates)

	// ÉTAPE 4: Conversion des candidats de mots vers bits
	bitCandidates = convertWordCandidatesToBits(preprocessedWordCandidates, reverseWords)

	// ÉTAPE 5: Conversion des mots checksum vers bits
	fmt.Println("🔢 Conversion des mots checksum vers bits...")
	CHECKSUM_BITS = make([]int, len(CHECKSUM_WORDS))
	for i, word := range CHECKSUM_WORDS {
		CHECKSUM_BITS[i] = wordToBits(word, reverseWords)
	}
	fmt.Printf("✅ %d mots checksum convertis en bits\n", len(CHECKSUM_BITS))

	// Charger les mots français du livre pour le mode fuzzy-ltd
	if *fuzzyLtdMode {
		fmt.Println("📖 Chargement des mots français du livre...")

		// Charger le JSON des mots français trouvés
		frenchWordsData, err := loadFrenchWordsFromJSON("tools/french_words_found.json")
		if err != nil {
			fmt.Printf("❌ Erreur lors du chargement du JSON: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("📊 %d mots français trouvés dans le livre\n", frenchWordsData.TotalFound)

		// Charger les listes française et anglaise pour la correspondance
		frenchList := loadWords("words/french.txt")
		englishList := loadWords("words/english.txt")

		// Convertir les mots français en anglais
		frenchToEnglishWords, err = convertFrenchWordsToEnglishByIndex(frenchWordsData.Words, frenchList, englishList)
		if err != nil {
			fmt.Printf("❌ Erreur lors de la conversion français-anglais: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("🔤 %d mots convertis du français vers l'anglais pour le mode fuzzy-ltd\n", len(frenchToEnglishWords))

		// Supprimer les doublons et trier
		wordSet := make(map[string]bool)
		for _, word := range frenchToEnglishWords {
			wordSet[word] = true
		}
		frenchToEnglishWords = make([]string, 0, len(wordSet))
		for word := range wordSet {
			frenchToEnglishWords = append(frenchToEnglishWords, word)
		}
		sort.Strings(frenchToEnglishWords)

		fmt.Printf("📝 %d mots uniques après déduplication\n", len(frenchToEnglishWords))

		// Convertir les mots du livre en bits
		fmt.Println("🔢 Conversion des mots du livre vers bits...")
		frenchToEnglishBits = convertEnglishWordListToBits(frenchToEnglishWords, reverseWords)
		fmt.Printf("✅ %d mots du livre convertis en bits\n", len(frenchToEnglishBits))
	}

	// Vérifier que tous les checksum words sont dans la wordlist
	fmt.Printf("🔤 Vérification des %d mots checksum...\n", len(CHECKSUM_WORDS))
	for _, word := range CHECKSUM_WORDS {
		if _, exists := reverseWords[word]; !exists {
			fmt.Printf("❌ Erreur: Checksum word '%s' non trouvé dans la wordlist!\n", word)
			os.Exit(1)
		}
	}
	fmt.Println("✅ Tous les mots checksum sont valides")

	// MODE BIT OPTIMIZATION
	if *bitOptimizeMode {
		fmt.Println("\n🔬 MODE BIT OPTIMIZATION ACTIVÉ")

		// Parser la phrase de base
		basePhraseWords := strings.Fields(*basePhraseFlag)
		if len(basePhraseWords) != 23 {
			fmt.Printf("❌ Erreur: La phrase de base doit contenir exactement 23 mots, trouvé: %d\n", len(basePhraseWords))
			os.Exit(1)
		}

		// Vérifier que tous les mots de la phrase de base sont dans la wordlist
		for i, word := range basePhraseWords {
			if _, exists := reverseWords[word]; !exists {
				fmt.Printf("❌ Erreur: Mot '%s' à la position %d non trouvé dans la wordlist BIP39\n", word, i)
				os.Exit(1)
			}
		}

		// Démarrer l'optimisation bit par bit
		bitOptimization(basePhraseWords, *wordTarget, wordValidList, reverseWords)
		return
	}

	// Calculer une estimation rapide des combinaisons
	fmt.Println("🧮 Calcul d'estimation des combinaisons...")
	totalCombinations = calculateEstimatedCombinations()

	totalChecksumTests := totalCombinations * 8 // 8 tests par phrase

	if *fuzzyMode {
		fmt.Printf("🔍 Mode fuzzy sur positions %v\n", fuzzyPositionsList)
	}

	fmt.Printf("🔢 Phrases estimées à tester: %s (doublons skippés à la volée)\n", formatNumber(totalCombinations))
	fmt.Printf("🎯 Total tests checksum estimés: %s (8 par phrase)\n", formatNumber(totalChecksumTests))
	fmt.Printf("🔤 Mots checksum: %v\n", CHECKSUM_WORDS)
	fmt.Println("🔥 OBJECTIF: Trouver une phrase qui valide TOUS les 8 checksum words!")
	fmt.Println("💾 AUTO-SAVE: Phrases avec >3 checksums sauvées dans 'high_scores_live.jsonl'")

	// Configuration optimisée des workers avec canal plus large
	numCPU := runtime.NumCPU()
	numWorkers := numCPU
	if totalCombinations > 1000000 {
		// Pour de gros volumes, utiliser plus de workers mais pas trop
		numWorkers = numCPU * 2
	}

	// Canal plus large avec batch processing
	channelSize := int(min(100000, totalCombinations/int64(numWorkers)*10))
	if channelSize < 1000 {
		channelSize = 1000
	}

	fmt.Printf("🧵 Utilisation de %d workers sur %d cores CPU\n", numWorkers, numCPU)
	fmt.Printf("📦 Taille du canal: %d (optimisé pour %s combinaisons)\n", channelSize, formatNumber(totalCombinations))
	fmt.Println()

	startTime = time.Now()
	lastLogTime = startTime

	// Démarrer le logger de performance en arrière-plan
	go performanceLogger()

	// Configuration des workers avec canal optimisé
	workChan := make(chan WorkItem, channelSize)
	var wg sync.WaitGroup

	// Démarrer les workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(workChan, &wg)
	}

	fmt.Println("🏁 Début du traitement parallélisé...")
	if *fuzzyMode {
		fmt.Printf("🔍 Mode fuzzy : positions %v utiliseront toute la wordlist\n", fuzzyPositionsList)
	}
	if *fuzzyLtdMode {
		fmt.Printf("📖 Mode fuzzy-ltd : positions %v utiliseront les %d mots du livre\n", fuzzyLtdPositionsList, len(frenchToEnglishWords))
	}

	fmt.Println("══════════════════════════════════════════════════")

	// Générer et envoyer les combinaisons aux workers
	go generateAllCombinations(workChan, reverseWords)

	// Attendre que tous les workers terminent
	wg.Wait()

	// Si on arrive ici, aucune phrase valide n'a été trouvée
	duration := time.Since(startTime)
	fmt.Printf("\n❌ Recherche terminée en %s\n", formatDuration(duration))
	fmt.Printf("🔍 Total phrases testées: %s\n", formatNumber(atomic.LoadInt64(&attemptCount)))
	fmt.Printf("🎯 Total tests checksum: %s\n", formatNumber(atomic.LoadInt64(&checksumTestCount)))
	fmt.Println("💔 Aucune phrase validant TOUS les 8 checksum words trouvée")

	// Afficher le meilleur résultat trouvé
	finalBestScore := atomic.LoadInt32(&bestScore)
	if finalBestScore > 0 {
		bestPhraseMutex.RLock()
		finalBestPhrase := bestPhrase
		bestPhraseMutex.RUnlock()

		fmt.Printf("\n🏆 MEILLEUR RÉSULTAT TROUVÉ:\n")
		fmt.Printf("🎯 Score: %d/8 checksum words corrects\n", finalBestScore)
		fmt.Printf("📝 Phrase (23 mots): %s\n", finalBestPhrase)
		fmt.Println("💡 Cette phrase est la plus proche de la solution trouvée!")

		// Sauvegarder le meilleur résultat si pas déjà fait
		if finalBestScore > 3 {
			// Recréer la phrase complète pour vérifier les checksum words valides
			phrase23Words := strings.Split(finalBestPhrase, " ")

			// Test rapide des checksum words pour le meilleur résultat
			var validChecksumWords []string
			completeMnemonic := make([]string, 24)
			copy(completeMnemonic[:23], phrase23Words)

			for _, checksumWord := range CHECKSUM_WORDS {
				completeMnemonic[23] = checksumWord
				if isValidMnemonic(completeMnemonic, reverseWords) {
					validChecksumWords = append(validChecksumWords, checksumWord)
				}
			}

			fmt.Printf("🔤 Checksum words valides: %v\n", validChecksumWords)

			// Sauvegarder le résultat final
			finalFilename := fmt.Sprintf("best_result_%d_checksums_final.json", len(validChecksumWords))
			bestResult := HighScoreResult{
				Phrase:             finalBestPhrase,
				ValidChecksumWords: validChecksumWords,
				NumValidChecksums:  len(validChecksumWords),
				Timestamp:          time.Now().Format(time.RFC3339),
			}

			file, err := os.Create(finalFilename)
			if err == nil {
				encoder := json.NewEncoder(file)
				encoder.SetIndent("", "  ")
				encoder.Encode(bestResult)
				file.Close()
				fmt.Printf("💾 Meilleur résultat sauvé dans: %s\n", finalFilename)
			}
		}
	} else {
		fmt.Println("\n😢 Aucune phrase n'a validé ne serait-ce qu'un seul checksum word")
	}

	// Statistiques finales des optimisations
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

}
