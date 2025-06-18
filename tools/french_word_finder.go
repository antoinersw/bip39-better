package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type WordMatch struct {
	Word  string `json:"word"`
	Index int    `json:"index"` // 1-based index in french.txt
}

type Results struct {
	Timestamp    string      `json:"timestamp"`
	TotalFound   int         `json:"total_found"`
	Words        []WordMatch `json:"words"`
	WordsSummary []string    `json:"words_summary"`
}

func main() {
	// Read French BIP39 word list
	frenchWords, err := readFrenchWords("../words/french.txt")
	if err != nil {
		fmt.Printf("Error reading French words: %v\n", err)
		return
	}

	// Read book content
	bookContent, err := readBookContent("../words/book.txt")
	if err != nil {
		fmt.Printf("Error reading book content: %v\n", err)
		return
	}

	// Find matches
	matches := findMatches(frenchWords, bookContent)

	// Sort by index
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Index < matches[j].Index
	})

	// Create summary
	var wordsSummary []string
	for _, match := range matches {
		wordsSummary = append(wordsSummary, fmt.Sprintf("%s(%d)", match.Word, match.Index))
	}

	// Create results structure
	results := Results{
		Timestamp:    time.Now().Format("2006-01-02T15:04:05-07:00"),
		TotalFound:   len(matches),
		Words:        matches,
		WordsSummary: wordsSummary,
	}

	// Write to JSON file
	outputFile := "french_words_found.json"
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	err = os.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	// Print summary to console
	fmt.Printf("Found %d French BIP39 words in the book\n", len(matches))
	fmt.Printf("Results written to: %s\n\n", outputFile)

	// Print first few matches as preview
	fmt.Println("Preview of found words:")
	for i, match := range matches {
		if i >= 10 { // Show only first 10
			fmt.Printf("... and %d more words\n", len(matches)-10)
			break
		}
		fmt.Printf("Index %d: %s\n", match.Index, match.Word)
	}
}

func readFrenchWords(filename string) (map[string]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	wordMap := make(map[string]int)
	scanner := bufio.NewScanner(file)
	index := 1

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordMap[word] = index
			index++
		}
	}

	return wordMap, scanner.Err()
}

func readBookContent(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func findMatches(frenchWords map[string]int, bookContent string) []WordMatch {
	// Convert book content to lowercase for case-insensitive matching
	bookLower := strings.ToLower(bookContent)

	// Create regex to split by spaces, hyphens, and apostrophes
	// Also include other common punctuation and special characters
	re := regexp.MustCompile(`[\s\-’'""«»,;.:!?()[\]{}…—–\n\r\t]+`)

	// Split the book content into words
	words := re.Split(bookLower, -1)

	// Create a map to track found words to avoid duplicates
	foundWords := make(map[string]bool)
	var matches []WordMatch

	// Check each word from the book against French BIP39 words
	for _, word := range words {
		// Clean the word (remove any remaining punctuation)
		cleanWord := cleanWord(word)
		if cleanWord == "" {
			continue
		}

		// Check if this word exists in French BIP39 list
		if index, exists := frenchWords[cleanWord]; exists {
			// Avoid duplicates
			if !foundWords[cleanWord] {
				foundWords[cleanWord] = true
				matches = append(matches, WordMatch{
					Word:  cleanWord,
					Index: index,
				})
			}
		}
	}

	return matches
}

func cleanWord(word string) string {
	// Remove any remaining punctuation and whitespace, keep only letters
	cleaned := regexp.MustCompile(`[^\p{L}]`).ReplaceAllString(word, "")
	return strings.TrimSpace(cleaned)
}
