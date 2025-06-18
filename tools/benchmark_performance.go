package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Structures pour les benchmarks
type BenchmarkResult struct {
	TestName           string
	SampleSize         int64
	TotalDuration      time.Duration
	PhrasesPerSecond   float64
	ChecksumsPerSecond float64
	MemoryUsedMB       float64
	CPUCores           int
	EstimatedFor1B     EstimatedPerformance
	EstimatedFor10B    EstimatedPerformance
	EstimatedFor100B   EstimatedPerformance
	ServerComparison   ServerComparison
}

type EstimatedPerformance struct {
	TotalPhrases    int64
	EstimatedTime   time.Duration
	EstimatedMemory string
	Feasibility     string
}

type ServerComparison struct {
	CurrentMachine ServerPerformance
	Server128Cores ServerPerformance
	Server96Cores  ServerPerformance
}

type ServerPerformance struct {
	Name             string
	CPUSpecs         string
	EstimatedSpeedup float64
	PhrasesPerSecond float64
	TimeFor10B       time.Duration
	TimeFor100B      time.Duration
	CostEfficiency   string
}

// Variables pour les benchmarks
var (
	benchmarkResults []BenchmarkResult
	logFile          *os.File
)

// Fonction pour initialiser le logging des performances
func initPerformanceLog() {
	var err error
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("performance_benchmark_%s.log", timestamp)

	logFile, err = os.Create(filename)
	if err != nil {
		log.Fatal("Impossible de créer le fichier de log:", err)
	}

	logInfo("🚀 BENCHMARK DE PERFORMANCE - OPTIMISATIONS BIP39")
	logInfo(strings.Repeat("=", 60))
	logInfo(fmt.Sprintf("Timestamp: %s", time.Now().Format(time.RFC3339)))
	logInfo(fmt.Sprintf("CPU Cores: %d", runtime.NumCPU()))
	logInfo(fmt.Sprintf("GOMAXPROCS: %d", runtime.GOMAXPROCS(0)))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logInfo(fmt.Sprintf("Memory Available: %.2f MB", float64(m.Sys)/1024/1024))
	logInfo("")
}

func logInfo(message string) {
	fmt.Println(message)
	if logFile != nil {
		logFile.WriteString(message + "\n")
		logFile.Sync()
	}
}

// Benchmark de la validation BIP39 optimisée
func benchmarkValidationOptimized(sampleSize int64) BenchmarkResult {
	logInfo(fmt.Sprintf("🧪 BENCHMARK: Validation BIP39 Optimisée (%d échantillons)", sampleSize))

	// Charger les mots BIP39
	wordList := loadBenchmarkWords("words/english.txt")
	reverseWords := make(map[string]int)
	for i, word := range wordList {
		reverseWords[word] = i
	}

	// Préparer un jeu de données test
	testPhrases := generateTestPhrases(sampleSize, reverseWords)
	checksum_bits := []int{45, 432, 1234, 1456, 1789} // 5 checksums de test

	var validCount int64
	var totalChecksums int64

	// Mesurer la mémoire avant
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	runtime.GC()
	runtime.ReadMemStats(&m1)

	startTime := time.Now()

	// Test de performance optimisé
	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU() * 2
	workChan := make(chan []int, 1000)

	// Lancer les workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for phrase23Bits := range workChan {
				// **TEST DE L'OPTIMISATION** : Pré-calculer l'entropy une seule fois
				entropy253 := computeBenchmarkPhrase23Entropy(phrase23Bits)

				// Tester avec tous les checksums (optimisé)
				for _, checksumBits := range checksum_bits {
					atomic.AddInt64(&totalChecksums, 1)
					if isBenchmarkChecksumValidForEntropy(entropy253, checksumBits) {
						atomic.AddInt64(&validCount, 1)
					}
				}
			}
		}()
	}

	// Envoyer le travail
	go func() {
		defer close(workChan)
		for _, phrase := range testPhrases {
			workChan <- phrase
		}
	}()

	wg.Wait()
	duration := time.Since(startTime)

	// Mesurer la mémoire après
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	memoryUsed := float64(m2.Alloc-m1.Alloc) / 1024 / 1024

	// Calculer les métriques
	phrasesPerSecond := float64(sampleSize) / duration.Seconds()
	checksumsPerSecond := float64(totalChecksums) / duration.Seconds()

	result := BenchmarkResult{
		TestName:           "Validation BIP39 Optimisée",
		SampleSize:         sampleSize,
		TotalDuration:      duration,
		PhrasesPerSecond:   phrasesPerSecond,
		ChecksumsPerSecond: checksumsPerSecond,
		MemoryUsedMB:       memoryUsed,
		CPUCores:           runtime.NumCPU(),
		EstimatedFor1B:     estimatePerformance(phrasesPerSecond, 1e9),
		EstimatedFor10B:    estimatePerformance(phrasesPerSecond, 10e9),
		EstimatedFor100B:   estimatePerformance(phrasesPerSecond, 100e9),
		ServerComparison:   calculateServerComparison(phrasesPerSecond),
	}

	logBenchmarkResult(result)
	return result
}

// Générer des phrases de test réalistes
func generateTestPhrases(count int64, reverseWords map[string]int) [][]int {
	// Mots candidats réalistes pour le benchmark
	candidateWords := []string{
		"erase", "miss", "oven", "father", "noise", "reward", "level", "blouse",
		"rotate", "admit", "helmet", "mansion", "rice", "very", "believe", "woman",
		"deny", "calm", "army", "fade", "alpha", "open", "always",
	}

	phrases := make([][]int, count)

	for i := int64(0); i < count; i++ {
		phrase := make([]int, 23)
		for j := 0; j < 23; j++ {
			word := candidateWords[j%len(candidateWords)]
			phrase[j] = benchmarkWordToBits(word, reverseWords)
		}
		phrases[i] = phrase
	}

	return phrases
}

// Estimation des performances pour grandes échelles
func estimatePerformance(phrasesPerSecond float64, totalPhrases int64) EstimatedPerformance {
	estimatedSeconds := float64(totalPhrases) / phrasesPerSecond
	estimatedDuration := time.Duration(estimatedSeconds) * time.Second

	// Estimation mémoire (approximative)
	memoryPerPhrase := 500.0 // bytes approximatifs par phrase
	totalMemoryBytes := float64(totalPhrases) * memoryPerPhrase
	memoryEstimate := formatMemoryEstimate(totalMemoryBytes)

	// Évaluation de faisabilité
	feasibility := "✅ EXCELLENT"
	if estimatedDuration > 24*time.Hour {
		feasibility = "⚠️ LONG (>24h)"
	}
	if estimatedDuration > 7*24*time.Hour {
		feasibility = "❌ TROP LONG (>1 semaine)"
	}

	return EstimatedPerformance{
		TotalPhrases:    totalPhrases,
		EstimatedTime:   estimatedDuration,
		EstimatedMemory: memoryEstimate,
		Feasibility:     feasibility,
	}
}

func formatMemoryEstimate(bytes float64) string {
	if bytes >= 1e12 {
		return fmt.Sprintf("%.1f TB", bytes/1e12)
	} else if bytes >= 1e9 {
		return fmt.Sprintf("%.1f GB", bytes/1e9)
	} else if bytes >= 1e6 {
		return fmt.Sprintf("%.1f MB", bytes/1e6)
	}
	return fmt.Sprintf("%.1f KB", bytes/1e3)
}

// Calculer les comparaisons de performance entre différents serveurs
func calculateServerComparison(basePhrasesPerSecond float64) ServerComparison {
	// Configuration actuelle (machine de l'utilisateur)
	currentMachine := ServerPerformance{
		Name:             "Machine Actuelle",
		CPUSpecs:         "Intel i9-13900H @ 2.60GHz (16 cores)",
		EstimatedSpeedup: 1.0,
		PhrasesPerSecond: basePhrasesPerSecond,
		TimeFor10B:       time.Duration(10e9/basePhrasesPerSecond) * time.Second,
		TimeFor100B:      time.Duration(100e9/basePhrasesPerSecond) * time.Second,
		CostEfficiency:   "✅ EXCELLENT (déjà possédé)",
	}

	// Serveur 128 cores @ 3.1GHz - estimation conservative
	// Facteur de scaling: (128 cores / 16 cores) * (3.1GHz / 2.6GHz) * efficiency_factor
	// efficiency_factor = 0.7 (scaling réel est rarement linéaire)
	speedup128 := (128.0 / 16.0) * (3.1 / 2.6) * 0.7
	phrases128 := basePhrasesPerSecond * speedup128

	server128 := ServerPerformance{
		Name:             "Serveur 128 Cores",
		CPUSpecs:         "128 cores @ 3.1GHz",
		EstimatedSpeedup: speedup128,
		PhrasesPerSecond: phrases128,
		TimeFor10B:       time.Duration(10e9/phrases128) * time.Second,
		TimeFor100B:      time.Duration(100e9/phrases128) * time.Second,
		CostEfficiency:   estimateCostEfficiency(speedup128, "high-end"),
	}

	// Serveur 96 cores (192 threads) @ 3.7GHz - estimation avec hyperthreading
	// Facteur de scaling: (96 cores / 16 cores) * (3.7GHz / 2.6GHz) * efficiency_factor
	// efficiency_factor = 0.65 (HT améliore moins pour ce type de calcul)
	speedup96 := (96.0 / 16.0) * (3.7 / 2.6) * 0.65
	phrases96 := basePhrasesPerSecond * speedup96

	server96 := ServerPerformance{
		Name:             "Serveur 96 Cores HT",
		CPUSpecs:         "96 cores / 192 threads @ 3.7GHz",
		EstimatedSpeedup: speedup96,
		PhrasesPerSecond: phrases96,
		TimeFor10B:       time.Duration(10e9/phrases96) * time.Second,
		TimeFor100B:      time.Duration(100e9/phrases96) * time.Second,
		CostEfficiency:   estimateCostEfficiency(speedup96, "premium"),
	}

	return ServerComparison{
		CurrentMachine: currentMachine,
		Server128Cores: server128,
		Server96Cores:  server96,
	}
}

func estimateCostEfficiency(speedup float64, serverClass string) string {
	var costMultiplier float64

	switch serverClass {
	case "high-end":
		costMultiplier = 25.0 // ~25x plus cher qu'un laptop
	case "premium":
		costMultiplier = 35.0 // ~35x plus cher qu'un laptop
	default:
		costMultiplier = 10.0
	}

	efficiencyRatio := speedup / costMultiplier

	if efficiencyRatio > 0.3 {
		return "✅ EXCELLENT ROI"
	} else if efficiencyRatio > 0.15 {
		return "⚠️ BON ROI"
	} else if efficiencyRatio > 0.05 {
		return "📊 ROI MOYEN"
	} else {
		return "❌ ROI FAIBLE"
	}
}

func logBenchmarkResult(result BenchmarkResult) {
	logInfo("")
	logInfo("📊 RÉSULTATS DU BENCHMARK:")
	logInfo(strings.Repeat("-", 40))
	logInfo(fmt.Sprintf("Test: %s", result.TestName))
	logInfo(fmt.Sprintf("Échantillons: %s", formatBenchmarkNumber(result.SampleSize)))
	logInfo(fmt.Sprintf("Durée totale: %v", result.TotalDuration))
	logInfo(fmt.Sprintf("Phrases/sec: %.0f", result.PhrasesPerSecond))
	logInfo(fmt.Sprintf("Checksums/sec: %.0f", result.ChecksumsPerSecond))
	logInfo(fmt.Sprintf("Mémoire utilisée: %.2f MB", result.MemoryUsedMB))
	logInfo(fmt.Sprintf("CPU Cores: %d", result.CPUCores))
	logInfo("")

	logInfo("🔮 ESTIMATIONS POUR GRANDES ÉCHELLES:")
	logInfo(strings.Repeat("-", 40))

	estimates := []struct {
		name string
		est  EstimatedPerformance
	}{
		{"1 Milliard", result.EstimatedFor1B},
		{"10 Milliards", result.EstimatedFor10B},
		{"100 Milliards", result.EstimatedFor100B},
	}

	for _, e := range estimates {
		logInfo(fmt.Sprintf("%s phrases:", e.name))
		logInfo(fmt.Sprintf("  ⏱️  Temps estimé: %v", formatDurationLong(e.est.EstimatedTime)))
		logInfo(fmt.Sprintf("  💾 Mémoire estimée: %s", e.est.EstimatedMemory))
		logInfo(fmt.Sprintf("  🎯 Faisabilité: %s", e.est.Feasibility))
	}
	logInfo("")

	// Afficher la comparaison des serveurs
	logServerComparison(result.ServerComparison)
}

func logServerComparison(comparison ServerComparison) {
	logInfo("🖥️ COMPARAISON SERVEURS HAUTE PERFORMANCE:")
	logInfo(strings.Repeat("-", 50))

	servers := []ServerPerformance{
		comparison.CurrentMachine,
		comparison.Server128Cores,
		comparison.Server96Cores,
	}

	for i, server := range servers {
		if i > 0 {
			logInfo("")
		}

		logInfo(fmt.Sprintf("📟 %s:", server.Name))
		logInfo(fmt.Sprintf("   🔧 Spécifications: %s", server.CPUSpecs))
		logInfo(fmt.Sprintf("   ⚡ Amélioration: %.1fx plus rapide", server.EstimatedSpeedup))
		logInfo(fmt.Sprintf("   🎯 Phrases/sec: %.0f", server.PhrasesPerSecond))
		logInfo(fmt.Sprintf("   ⏱️  10 milliards: %v", formatDurationLong(server.TimeFor10B)))
		logInfo(fmt.Sprintf("   ⏱️  100 milliards: %v", formatDurationLong(server.TimeFor100B)))
		logInfo(fmt.Sprintf("   💰 Coût/Efficacité: %s", server.CostEfficiency))
	}

	logInfo("")
	logInfo("🎯 RECOMMANDATIONS SERVEURS:")

	// Déterminer le meilleur choix
	best128Time := comparison.Server128Cores.TimeFor100B
	best96Time := comparison.Server96Cores.TimeFor100B

	if best128Time < best96Time {
		logInfo("   🏆 MEILLEUR CHOIX: Serveur 128 cores")
		logInfo(fmt.Sprintf("      ⚡ 100 milliards en seulement %v", formatDurationLong(best128Time)))
		if best128Time < 24*time.Hour {
			logInfo("      ✅ TRAITEMENT EN MOINS DE 24H!")
		}
	} else {
		logInfo("   🏆 MEILLEUR CHOIX: Serveur 96 cores (192 threads)")
		logInfo(fmt.Sprintf("      ⚡ 100 milliards en %v", formatDurationLong(best96Time)))
	}

	// Recommandations spécifiques
	if comparison.CurrentMachine.TimeFor10B < 24*time.Hour {
		logInfo("   ✅ Votre machine actuelle: PARFAITE pour 10 milliards")
	}

	if best128Time > 7*24*time.Hour {
		logInfo("   ⚠️  Même avec serveur: 100 milliards reste un défi")
		logInfo("   💡 Conseil: Traitement par batch de 10 milliards")
	}

	logInfo("")
}

func formatDurationLong(d time.Duration) string {
	if d.Hours() >= 24*365 {
		return fmt.Sprintf("%.1f ans", d.Hours()/(24*365))
	} else if d.Hours() >= 24*30 {
		return fmt.Sprintf("%.1f mois", d.Hours()/(24*30))
	} else if d.Hours() >= 24*7 {
		return fmt.Sprintf("%.1f semaines", d.Hours()/(24*7))
	} else if d.Hours() >= 24 {
		return fmt.Sprintf("%.1f jours", d.Hours()/24)
	} else if d.Hours() >= 1 {
		return fmt.Sprintf("%.1f heures", d.Hours())
	} else if d.Minutes() >= 1 {
		return fmt.Sprintf("%.1f minutes", d.Minutes())
	}
	return fmt.Sprintf("%.1f secondes", d.Seconds())
}

func formatBenchmarkNumber(n int64) string {
	if n >= 1e12 {
		return fmt.Sprintf("%.1fT", float64(n)/1e12)
	} else if n >= 1e9 {
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	} else if n >= 1e6 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	} else if n >= 1e3 {
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

// Fonctions utilitaires spécifiques au benchmark
func loadBenchmarkWords(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}
	return words
}

func benchmarkWordToBits(word string, reverseWords map[string]int) int {
	if bits, ok := reverseWords[word]; ok {
		return bits
	}
	return -1
}

// Fonctions optimisées pour benchmark
func computeBenchmarkPhrase23Entropy(phrase23Bits []int) *big.Int {
	entropy253 := new(big.Int)

	for _, wordBits := range phrase23Bits {
		entropy253.Lsh(entropy253, 11)
		entropy253.Add(entropy253, big.NewInt(int64(wordBits)))
	}

	return entropy253
}

func isBenchmarkChecksumValidForEntropy(entropy253 *big.Int, checksumBits int) bool {
	entropy256 := new(big.Int).Set(entropy253)
	entropy256.Lsh(entropy256, 3)

	topBits := (checksumBits >> 8) & 0x7
	entropy256.Or(entropy256, big.NewInt(int64(topBits)))

	expectedChecksum := computeBenchmarkChecksumFast(entropy256)
	actualChecksum := checksumBits & 0xFF

	return actualChecksum == expectedChecksum
}

func computeBenchmarkChecksumFast(entropy256 *big.Int) int {
	entropyBytes := entropy256.Bytes()

	if len(entropyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(entropyBytes):], entropyBytes)
		entropyBytes = padded
	} else if len(entropyBytes) > 32 {
		entropyBytes = entropyBytes[len(entropyBytes)-32:]
	}

	// SHA256 pour le checksum
	hash := sha256.Sum256(entropyBytes)
	return int(hash[0])
}

func runBenchmark() {
	initPerformanceLog()
	defer logFile.Close()

	logInfo("🎯 DÉMARRAGE DES BENCHMARKS DE PERFORMANCE")
	logInfo("")

	// Tests avec différentes tailles d'échantillons
	sampleSizes := []int64{1000, 10000, 100000}

	for _, size := range sampleSizes {
		result := benchmarkValidationOptimized(size)
		benchmarkResults = append(benchmarkResults, result)

		// Attendre un peu entre les tests
		time.Sleep(2 * time.Second)
		runtime.GC() // Force garbage collection
	}

	// Résumé final
	logInfo("📈 RÉSUMÉ FINAL DES PERFORMANCES:")
	logInfo(strings.Repeat("=", 60))

	if len(benchmarkResults) > 0 {
		bestResult := benchmarkResults[len(benchmarkResults)-1] // Plus gros échantillon

		logInfo(fmt.Sprintf("🏆 MEILLEURE PERFORMANCE (échantillon %s):", formatBenchmarkNumber(bestResult.SampleSize)))
		logInfo(fmt.Sprintf("   Phrases/sec: %.0f", bestResult.PhrasesPerSecond))
		logInfo(fmt.Sprintf("   Checksums/sec: %.0f", bestResult.ChecksumsPerSecond))
		logInfo("")

		logInfo("🎯 RECOMMANDATIONS FINALES POUR VOS MILLIARDS DE DONNÉES:")

		// Recommandations basées sur la machine actuelle
		if bestResult.EstimatedFor10B.Feasibility == "✅ EXCELLENT" {
			logInfo("   ✅ 10 milliards: FAISABLE sur votre machine actuelle")
			logInfo(fmt.Sprintf("      Temps estimé: %v", formatDurationLong(bestResult.EstimatedFor10B.EstimatedTime)))
		}

		// Recommandations serveurs
		server128Time := bestResult.ServerComparison.Server128Cores.TimeFor100B

		logInfo("")
		logInfo("💰 ANALYSE COÛT/BÉNÉFICE:")

		if bestResult.EstimatedFor10B.EstimatedTime < 48*time.Hour {
			logInfo("   🏆 DÉCISION: Restez sur votre machine actuelle")
			logInfo("   💡 10 milliards = traitement optimal sans investissement")
		} else if server128Time < 24*time.Hour {
			logInfo("   🏆 DÉCISION: Investir dans serveur 128 cores")
			logInfo(fmt.Sprintf("   ⚡ 100 milliards en %v (ROI excellent)", formatDurationLong(server128Time)))
		} else {
			logInfo("   🏆 DÉCISION: Traitement par batch recommandé")
			logInfo("   💡 10 milliards par batch sur votre machine actuelle")
		}
	}

	logInfo("")
	logInfo("✅ BENCHMARK TERMINÉ - Résultats sauvés dans le fichier log")
}

func main() {
	fmt.Println("🚀 Lancement du benchmark de performance...")
	runBenchmark()
}
