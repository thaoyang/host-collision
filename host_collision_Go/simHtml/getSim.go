package simHtml

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// File interface
func GetSimFromFile(file1, file2 string) float64 {
	cont1, _ := os.ReadFile(file1)
	doc1, _ := goquery.NewDocumentFromReader(bytes.NewReader(cont1))
	cont2, _ := os.ReadFile(file2)
	doc2, _ := goquery.NewDocumentFromReader(bytes.NewReader(cont2))
	return GetSimRate(doc1, doc2)
}

// String interface
func GetSimFromStr(s1 string, s2 string) float64 {
	// Convert string to io.Reader
	reader1 := strings.NewReader(s1)
	// Convert io.Reader to goquery.Document
	doc1, err := goquery.NewDocumentFromReader(reader1)
	if err != nil {
		log.Fatalf("Failed to parse HTML: %v", err)
	}
	// Convert string to io.Reader
	reader2 := strings.NewReader(s2)
	// Convert io.Reader to goquery.Document
	doc2, err := goquery.NewDocumentFromReader(reader2)
	if err != nil {
		log.Fatalf("Failed to parse HTML: %v", err)
	}
	return GetSimRate(doc1, doc2)
}

// Url interface
func GetSimFromUrl(url1, url2 string) float64 {
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	resp1, err := http.Get(url1)
	if err != nil {
		fmt.Println(err)
		return 0
	}
	defer resp1.Body.Close()
	resp2, err := http.Get(url2)
	if err != nil {
		fmt.Println(err)
		return 0
	}
	defer resp2.Body.Close()
	doc1, _ := goquery.NewDocumentFromReader(resp1.Body)
	doc2, _ := goquery.NewDocumentFromReader(resp2.Body)
	return GetSimRate(doc1, doc2)
}
