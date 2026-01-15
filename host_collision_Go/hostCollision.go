package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"main/simHtml"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var logger = logrus.New()

// IP rate limiter structure
type IPRateLimiter struct {
	mu                 sync.Mutex
	lastRequestTime    map[string]time.Time // Last request time for each IP
	requestCount       map[string]int       // Consecutive request count for each IP
	pauseUntil         map[string]time.Time // Pause deadline for each IP
	maxRequestsPerIP   int                  // Maximum consecutive requests per IP
	pauseDuration      time.Duration        // Pause duration
	minRequestInterval time.Duration        // Minimum request interval (1 second)
}

// Create a new IP rate limiter
func NewIPRateLimiter(maxRequests int, pauseDuration time.Duration, minInterval time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		lastRequestTime:    make(map[string]time.Time),
		requestCount:       make(map[string]int),
		pauseUntil:         make(map[string]time.Time),
		maxRequestsPerIP:   maxRequests,
		pauseDuration:      pauseDuration,
		minRequestInterval: minInterval,
	}
}

// Extract IP address from URL
func extractIPFromURL(urlStr string) string {
	// Remove protocol prefix (http:// or https://)
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	// Handle IPv6 address format [::1]
	if strings.HasPrefix(urlStr, "[") {
		end := strings.Index(urlStr, "]")
		if end > 0 {
			return urlStr[1:end]
		}
	}

	// Handle IPv4 or IPv6 address (without brackets)
	// Extract IP part (may contain port, but we only need IP here)
	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		ipPart := parts[0]
		// Remove port number (if any)
		if colonIdx := strings.LastIndex(ipPart, ":"); colonIdx > 0 {
			// Check if it's an IPv6 address (IPv6 addresses may contain multiple colons)
			if strings.Count(ipPart, ":") > 1 {
				// IPv6 address, don't process
				return ipPart
			}
			// IPv4 address with port, remove port
			return ipPart[:colonIdx]
		}
		return ipPart
	}
	return urlStr
}

// Check if a request can be sent, and update state if possible
func (rl *IPRateLimiter) CanSendRequest(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Check if in pause period
	if pauseTime, exists := rl.pauseUntil[ip]; exists {
		if now.Before(pauseTime) {
			// Still in pause period, cannot send
			return false
		}
		// Pause period has passed, clear pause state and counter
		delete(rl.pauseUntil, ip)
		rl.requestCount[ip] = 0
	}

	// Check request interval (maximum 1 request per second)
	if lastTime, exists := rl.lastRequestTime[ip]; exists {
		elapsed := now.Sub(lastTime)
		if elapsed < rl.minRequestInterval {
			// Request interval too short, need to wait
			return false
		}
	}

	// Update request count
	rl.requestCount[ip]++

	// Check if maximum request count is reached
	if rl.requestCount[ip] >= rl.maxRequestsPerIP {
		// Reached limit, set pause time
		rl.pauseUntil[ip] = now.Add(rl.pauseDuration)
		rl.requestCount[ip] = 0 // Reset counter
		logger.Info(fmt.Sprintf("IP %s reached %d requests, pausing for %v", ip, rl.maxRequestsPerIP, rl.pauseDuration))
	}

	// Update last request time
	rl.lastRequestTime[ip] = now

	return true
}

// Wait until a request can be sent
func (rl *IPRateLimiter) WaitUntilCanSend(ip string) {
	for {
		if rl.CanSendRequest(ip) {
			return
		}

		rl.mu.Lock()
		now := time.Now()
		var waitTime time.Duration

		// Calculate wait time needed
		if pauseTime, exists := rl.pauseUntil[ip]; exists {
			// In pause period
			waitTime = pauseTime.Sub(now)
		} else if lastTime, exists := rl.lastRequestTime[ip]; exists {
			// Need to wait for request interval
			elapsed := now.Sub(lastTime)
			if elapsed < rl.minRequestInterval {
				waitTime = rl.minRequestInterval - elapsed
			}
		}
		rl.mu.Unlock()

		if waitTime > 0 {
			if waitTime > time.Second {
				logger.Debug(fmt.Sprintf("IP %s waiting for %v", ip, waitTime))
			}
			time.Sleep(waitTime)
		} else {
			// Retry after brief wait
			time.Sleep(100 * time.Millisecond)
		}
	}
}

type Response struct {
	URL        string `json:"url"`
	IP         string `json:"ip"`
	Host       string `json:"host"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size"`
	Title      string `json:"title"`
	PatchData  string `json:"patchdata"`
	Headers    bson.M `json:"headers"`
	Isinetdm   string `json:"isinetdm"`
}

// Check if a collection exists in the database
func collectionExists(database *mongo.Database, collectionName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Timeout handling
	defer cancel()
	collections, err := database.ListCollectionNames(ctx, bson.D{}) // List collection names in the database
	if err != nil {
		return false, err
	}
	for _, name := range collections { // Check if target collection is in the collection list
		if name == collectionName {
			return true, nil
		}
	}
	return false, nil
}

// Replace invalid UTF-8 characters with a specified character, e.g., "?"
func replaceInvalidUTF8(input string) string {
	valid := make([]rune, 0, len(input))
	for i := 0; i < len(input); {
		r, size := utf8.DecodeRuneInString(input[i:])
		if r == utf8.RuneError && size == 1 {
			valid = append(valid, '?') // Replace invalid character
			i++
		} else {
			valid = append(valid, r)
			i += size
		}
	}
	return string(valid)
}

// Store results to MongoDB
func storeResultsToMongoDB(res *Response, collection *mongo.Collection, filter200 bool) {
	if !filter200 {
		_, err := collection.InsertOne(context.TODO(), bson.D{
			{"url", res.URL},
			{"ip", res.IP},
			{"host", res.Host},
			{"status_code", res.StatusCode},
			{"size", res.Size},
			{"title", replaceInvalidUTF8(res.Title)},
			{"patchdata", replaceInvalidUTF8(res.PatchData)},
			{"headers", res.Headers},
			{"isinetdm", res.Isinetdm},
		})
		if err != nil {
			logger.Error("Error inserting into MongoDB: ", err)
		}
	} else {
		if res.StatusCode >= 200 && res.StatusCode < 400 {
			_, err := collection.InsertOne(context.TODO(), bson.D{
				{"url", res.URL},
				{"ip", res.IP},
				{"host", res.Host},
				{"status_code", res.StatusCode},
				{"size", res.Size},
				{"title", replaceInvalidUTF8(res.Title)},
				{"patchdata", replaceInvalidUTF8(res.PatchData)},
				{"headers", res.Headers},
				{"isinetdm", res.Isinetdm},
			})
			if err != nil {
				logger.Error("Error inserting into MongoDB: ", err)
			}
		}
	}
}

func processRequests(client *mongo.Client, sld string, ips []string, Hosts map[string]interface{}, maxConcurrentRequests int, sld_id interface{}, RecheckInetdm bool) {
	// Create IP rate limiter: maximum 1 request per second per IP, pause for 1 hour after 10,000 consecutive requests
	ipRateLimiter := NewIPRateLimiter(10000, 1*time.Hour, 1*time.Second)

	// Generate test data
	var urls []string
	for _, ip := range ips {
		// Generate https URL
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			fmt.Printf("Skipping invalid IP: %s\n", ip) // Skip processing if IP is invalid
			continue
		}
		if parsedIP.To4() != nil {
			urls = append(urls, fmt.Sprintf("https://%s", ip)) // IPv4 address
		} else {
			urls = append(urls, fmt.Sprintf("https://[%s]", ip)) // IPv6 address
		}
	}
	for _, ip := range ips {
		// Generate http URL
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			fmt.Printf("Skipping invalid IP: %s\n", ip) // Skip processing if IP is invalid
			continue
		}
		if parsedIP.To4() != nil {
			urls = append(urls, fmt.Sprintf("http://%s", ip)) // IPv4 address
		} else {
			urls = append(urls, fmt.Sprintf("http://[%s]", ip)) // IPv6 address
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // Set database read timeout to 600s
	defer cancel()

	semaphore := make(chan struct{}, maxConcurrentRequests) // Semaphore to control the number of goroutines sending HTTP requests

	// Generate control group
	logger.Info("Processing IPControl...")
	db := client.Database("hosts-ok-ipcontrol-1") // Create database
	ipcontrol_cl_name := sld + "-IPcontrol"
	ipcontrolExist, err := collectionExists(db, ipcontrol_cl_name)
	ipcontrol_collection := db.Collection(ipcontrol_cl_name) // Database collection for reading and writing
	if !ipcontrolExist {
		// If it doesn't exist, get control group data and write to control group database
		var wg3 sync.WaitGroup // Consumer goroutine control
		var wg4 sync.WaitGroup // Producer goroutine control
		ipResults := make(chan *Response, maxConcurrentRequests)

		wg3.Add(1)
		go func() {
			defer wg3.Done()
			for res := range ipResults {
				storeResultsToMongoDB(res, ipcontrol_collection, false)
			}
		}()

		for _, host := range []string{sld, "", "xxxyyyzzz." + sld, "A123.123-b.c-123." + sld} { // As producer, send HTTP requests to channel, control maximum goroutine concurrency via semaphore
			for _, url := range urls { // Control group consists of four HTTP request structures: host as sld, without host, two subdomains that likely don't exist
				wg4.Add(1)
				semaphore <- struct{}{} // Semaphore controls maximum number of running goroutines
				go func(url string, host string) {
					defer func() {
						<-semaphore
						wg4.Done()
					}() // release semaphore

					// Extract IP and apply rate limiting
					ip := extractIPFromURL(url)
					ipRateLimiter.WaitUntilCanSend(ip)

					var finalRes *Response
					// Try 5 requests, each with one retry in between, so maximum 10 attempts
					for i := 0; i < 5; i++ {
						// Check rate limit before each retry
						if i > 0 {
							ipRateLimiter.WaitUntilCanSend(ip)
						}
						res := getPageContent(url, host)
						if res.StatusCode != 0 {
							finalRes = res
							break
						}
						// Record the last request result
						if i == 4 {
							finalRes = res
						}
						// If not the last request, wait 1 second
						if i < 4 {
							time.Sleep(1 * time.Second)
						}
					}

					if finalRes != nil {
						finalRes.Isinetdm = "ManualSet"
						ipResults <- finalRes
					}
				}(url, host)
			}
		}

		wg4.Wait()
		close(ipResults) // Close channel to ensure consumer exits without blocking after reading channel completes
		wg3.Wait()
		logger.Info("IPControl has generated successfully!")
	}
	logger.Info("Reading IPControl and Initializing inputs...")
	cursor, err := ipcontrol_collection.Find(ctx, bson.M{}) // Query all records
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer cursor.Close(ctx)
	type ctrolRecord struct { // Define query structure
		Statuscode int
		Title      string
		Patchdata  string
	}
	urlMap := make(map[string][]ctrolRecord) // Initialize map
	for cursor.Next(ctx) {
		// Iterate through query results
		var result struct {
			URL        string `bson:"url"`
			Statuscode int    `bson:"status_code"`
			Title      string `bson:"title"`
			Patchdata  string `bson:"patchdata"`
		}

		if err := cursor.Decode(&result); err != nil {
			log.Fatalf("Failed to decode record: %v", err)
		}

		if result.Statuscode == 0 {
			continue
		}

		urlMap[result.URL] = append(urlMap[result.URL], ctrolRecord{ // Store new record in urlMap
			Statuscode: result.Statuscode,
			Title:      result.Title,
			Patchdata:  result.Patchdata,
		})
	}

	// HC testing
	urls = []string{} // Extract all keys (URLs) and store in slice, updating url slice to exclude unreachable IPs due to timeout
	for url := range urlMap {
		urls = append(urls, url)
	}
	if err := cursor.Err(); err != nil {
		log.Fatalf("Failed to iterate records: %v", err)
	} else if !RecheckInetdm {
		update_info := bson.M{
			"$set": bson.M{
				"validurls": len(urls),
			},
		}
		db_for_collision := client.Database("ForCollision")
		AllMidInfo := db_for_collision.Collection("AllMidInfo")
		AllMidInfo.UpdateOne(ctx, bson.M{"_id": sld_id}, update_info)
		logger.Info(fmt.Sprintf("\nUrlnum For HostCollision: %d", len(urls)))
	}
	db = client.Database("hosts-ok-1")
	hc_ok_name := sld + "-hosts_ok"
	hc_ok_collection := db.Collection(hc_ok_name)
	hcResults := make(chan *Response, maxConcurrentRequests)
	var wg1 sync.WaitGroup // Consumer goroutine control
	var wg2 sync.WaitGroup // Producer goroutine control
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for res := range hcResults {
			queryURL := res.URL
			found := true
			if records, exists := urlMap[queryURL]; exists {
				for _, record := range records {
					if record.Statuscode != res.StatusCode {
						continue
					}
					title := record.Title
					if title != "" && title == res.Title {
						found = false
						break
					}

					patchdata := record.Patchdata
					if patchdata == res.PatchData {
						found = false
						break
					} else if simHtml.GetSimFromStr(patchdata, res.PatchData) > 0.8 {
						found = false
						break
					}
				}
				if found {
					storeResultsToMongoDB(res, hc_ok_collection, false)
				}
			} else {
				logger.Info("No records found for URL: " + queryURL)
			}
		}
	}()

	logger.Info(fmt.Sprintf("Host Collision Testing, InetdmRecheck is %t...", RecheckInetdm))

	db = client.Database("hosts-ok-supervisor-1")
	spv_host := sld + "-host"
	host_collection := db.Collection(spv_host)

	for host, hostInfo := range Hosts { // As producer, iterate through Hosts, send HTTP requests to channel, control maximum goroutine concurrency via semaphore
		// Type assertion to get isinetdm value
		info, ok := hostInfo.(map[string]interface{})
		if !ok {
			continue
		}
		isinetdm, ok := info["isinetdm"].(string)
		if !ok {
			isinetdm = "false" // Default value
		}
		id := info["_id"]

		for _, url := range urls {
			wg2.Add(1)
			semaphore <- struct{}{}
			go func(url string, host string, isinetdm string) {
				defer func() {
					<-semaphore
					wg2.Done()
				}()

				// Extract IP and apply rate limiting
				ip := extractIPFromURL(url)
				ipRateLimiter.WaitUntilCanSend(ip)

				res := getPageContent(url, host)
				if res != nil {
					res.Isinetdm = isinetdm
					hcResults <- res
				}
			}(url, host, isinetdm)
		}
		if !RecheckInetdm {
			// Find document with _id matching Host[host] value and update its "haschecked" field to 1
			filter := bson.D{{"_id", id}}
			update := bson.D{{"$set", bson.D{{"haschecked", 1}}}}
			_, err := host_collection.UpdateOne(context.TODO(), filter, update)
			if err != nil {
				logger.Error("Error updating 'haschecked' field in MongoDB: ", err)
			}
		}
	}
	wg2.Wait()
	close(hcResults) // Close channel to ensure consumer exits without blocking after reading channel completes
	wg1.Wait()
}

// Get title content
func getTitle(body string) string {
	re := regexp.MustCompile(`<title>([\s\S]*?)</title>`)
	match := re.FindStringSubmatch(body)
	if match != nil && len(match) > 1 {
		return strings.TrimSpace(match[1])
	} else {
		return ""
	}
}

// Send HTTP request with Host header added
func getPageContent(urlStr string, hostName string) *Response {
	//display 'Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>' error
	log.SetOutput(io.Discard)

	//display "ERROR RESTY" error
	logger := logrus.New()
	logger.Out = io.Discard

	client := resty.New().SetLogger(logger)
	// Ignore certificate errors
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	// Set timeout
	client.SetTimeout(time.Duration(3 * time.Second)) // Set timeout to 3s
	// Set request headers
	if hostName != "" {
		client.SetHeaders(map[string]string{
			"Host":            hostName,
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
			"Accept-Encoding": "gzip",
		})
	} else {
		client.SetHeaders(map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
			"Accept-Encoding": "gzip",
		})
	}
	// Disable automatic redirect
	client.SetRedirectPolicy(resty.NoRedirectPolicy())
	// Immediately close TCP connection when GET request ends, reduce server load
	client.SetCloseConnection(true)

	// Retry 1 time, with 2s interval
	client.SetRetryCount(1).SetRetryWaitTime(2 * time.Second).SetRetryMaxWaitTime(3 * time.Second)

	// Send HTTP request
	resp, err := client.R().Get(urlStr)
	if err != nil {
		// fmt.Println(err)
		if resp == nil {
			return &Response{
				URL:        urlStr,
				IP:         strings.Split(urlStr, "//")[1], // Extract IP from URL
				Host:       hostName,
				StatusCode: 0,
				Size:       0,
				Title:      "",
				PatchData:  err.Error(),
				Headers:    nil,
			}
		} else {
			statusCode := resp.StatusCode()
			// Collect error response header information
			headers := make(bson.M)
			for k, v := range resp.Header() {
				headers[k] = v
			}
			if statusCode > 300 && statusCode < 400 {
				if locations, exists := resp.RawResponse.Header["Location"]; exists && len(locations) > 0 {
					// Get the first value of Location field
					location := locations[0]
					return &Response{
						URL:        urlStr,
						IP:         strings.Split(urlStr, "//")[1], // Extract IP from URL
						Host:       hostName,
						StatusCode: resp.StatusCode(),
						Size:       0,
						Title:      location,
						PatchData:  err.Error(),
						Headers:    headers,
					}
				}
			}
			return &Response{
				URL:        urlStr,
				IP:         strings.Split(urlStr, "//")[1], // Extract IP from URL
				Host:       hostName,
				StatusCode: resp.StatusCode(),
				Size:       0,
				Title:      "",
				PatchData:  err.Error(),
				Headers:    headers,
			}
		}
	} else {
		// Read HTTP response content
		body := resp.String()
		title := getTitle(body)
		lenPage := len(body)
		// Truncate returned content to avoid excessive memory usage
		if lenPage > 500 {
			body = body[:500]
		}
		statusCode := resp.StatusCode()
		headers := make(bson.M)
		for k, v := range resp.Header() {
			headers[k] = v
		}

		return &Response{
			URL:        urlStr,
			IP:         strings.Split(urlStr, "//")[1], // Extract IP from URL
			Host:       hostName,
			StatusCode: statusCode,
			Size:       lenPage,
			Title:      title,
			PatchData:  body,
			Headers:    headers,
		}
	}
}

func readFile2Slice(filepath string) (Lines []string, err error) {

	file, err := os.Open(filepath) // Open file
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return nil, err
	}
	defer file.Close()

	var lines []string // Create a slice to store file content

	scanner := bufio.NewScanner(file) // Use bufio.Scanner to read file content line by line
	for scanner.Scan() {
		if scanner.Text() != "" { // Exclude empty strings
			lines = append(lines, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil { // Check for errors during reading
		fmt.Printf("Error reading file: %v\n", err)
		return nil, err
	}
	return lines, nil
}

// Calculate the number of domain levels
func getDMTierNums(hostname string) int {
	// Remove trailing dot (if any)
	if strings.HasSuffix(hostname, ".") {
		hostname = strings.TrimSuffix(hostname, ".")
	}
	// Split by "." and return the number of parts
	return len(strings.Split(hostname, "."))
}

// Get the numth part of the domain (from right to left)
func getSLD(domain string, numth int) (string, bool) {
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")
	// Split domain by "."
	domainParts := strings.Split(domain, ".")
	// If the number of domain parts is less than numth, return false
	if len(domainParts) < numth {
		return "", false
	}
	return domainParts[len(domainParts)-numth], true
}

// Random sampling function
func sample(slice []string, n int) []string {
	if n >= len(slice) {
		return slice
	}

	// Create a local random number generator
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Shuffle slice content
	r.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})

	// Return the first n elements
	return slice[:n]
}

func isValidDomain(domain string) bool {
	// Regular expression for domain names
	// Matches: valid domains like example.com, sub.domain.org, xn--fiq228c.com, etc.
	domainRegex := `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(domainRegex, domain)
	return matched
}

// Check if it's a public IP address
func isPublicIP(ipAddress string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		fmt.Printf("Invalid IP address: %s\n", ipAddress)
		return false
	}

	// Private address ranges
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // CGNAT range
	}

	// Link-local and multicast address ranges
	reservedCIDRs := []string{
		"169.254.0.0/16", // Link-local address
		"224.0.0.0/4",    // Multicast address
		"240.0.0.0/4",    // Reserved address
		"::1/128",        // IPv6 loopback address
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 link-local address
		"ff00::/8",       // IPv6 multicast address
	}

	// Check if it's a loopback address
	if ip.IsLoopback() {
		return false
	}

	// Check if it's a private or reserved address
	for _, cidr := range append(privateCIDRs, reservedCIDRs...) {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return false
		}
	}

	// If not in the above ranges, it's a public address
	return true
}

func DomainProperty(domain string) (IsNon bool, IsInet bool, IsPub bool, Error error) {
	// Create two DNS messages for IPv4 and IPv6 requests respectively
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)

	// Set up DNS client
	client := &dns.Client{
		Timeout: 2 * time.Second, // Set timeout to 2 seconds
	}
	// Use specified DNS server
	dnsServer := "114.114.114.114:53"
	Error = nil

	// Execute IPv4 query
	IsInet_A, IsNon_A := false, false
	responseA, _, err := client.Exchange(msgA, dnsServer)
	if err == nil {
		if len(responseA.Answer) == 0 { // Check if the answer section of the response is empty
			IsNon_A = true
		} else {
			canary := true // canary is used to exclude cases where len()>0 but it's not IPv4
			for _, answer := range responseA.Answer {
				if a, ok := answer.(*dns.A); ok {
					canary = false
					if !isPublicIP(a.A.String()) {
						IsInet_A = true
						break
					}
				}
			}
			if canary {
				IsInet_A = true
			}
		}
	} else {
		IsNon_A = true
		Error = err
	}

	// Execute IPv6 query
	IsInet_AAAA, IsNon_AAAA := false, false
	responseAAAA, _, err := client.Exchange(msgAAAA, dnsServer)
	if err == nil {
		if len(responseAAAA.Answer) == 0 { // Check if the answer section of the response is empty
			IsNon_AAAA = true
		} else {
			canary := true // canary is used to exclude cases where len()>0 but it's not IPv4
			for _, answer := range responseAAAA.Answer {
				if a, ok := answer.(*dns.AAAA); ok {
					canary = false
					if !isPublicIP(a.AAAA.String()) {
						IsInet_AAAA = true
						break
					}
				}
			}
			if canary {
				IsInet_AAAA = true
			}
		}
	} else {
		IsNon_AAAA = true
		Error = err
	}

	IsNon = IsNon_A && IsNon_AAAA
	IsInet = IsInet_A || IsInet_AAAA
	if (!IsNon) && (!IsInet) {
		IsPub = true
	} else {
		IsPub = false
	}

	return
}

func main() {
	sld := flag.String("sld", "", "SLD to be checked")
	maxConcurrentRequests := flag.Int("t", 0, "Number of goroutines")
	useDNS := flag.Bool("D", false, "whether use DNS to filter nonDMs")
	maxDNSRequests := flag.Int("DNSt", 500, "Number of goroutines")
	RecheckInetdm := flag.Bool("RecheckInetdm", false, "whether Recheck Inetdm")

	flag.Parse() // Parse command line flags

	if *sld == "" {
		logger.Error("Parameter --sld Must be inputted!")
		return // Missing return statement, added so program exits when parameter is missing
	}

	// Connect to database
	clientOptions := options.Client().ApplyURI("mongodb://HostCollision:H0stC0111s10n@202.112.47.70:27017") // As consumer, read from channel and write to database
	client, err := mongo.Connect(context.TODO(), clientOptions)                                             // Connect to MongoDB
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	err = client.Ping(context.TODO(), nil) // Ensure connection is successful
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}
	defer client.Disconnect(context.TODO()) // Close connection
	logger.Info("Successfully connected to MongoDB")

	// Determine the _id value of sld to write in AllMidInfo
	db_for_collision := client.Database("ForCollision")
	AllMidInfo := db_for_collision.Collection("AllMidInfo")
	filter := bson.D{{"sld", *sld}}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	var result bson.M
	err = AllMidInfo.FindOne(ctx, filter).Decode(&result)
	var sld_id interface{} = false
	if err == nil {
		sld_id = result["_id"]
	} else if err == mongo.ErrNoDocuments {
		// Keep sld_id as false
	} else {
		logger.Error(fmt.Sprintf("Query failed: %v", err))
		return
	}

	// Read IPs from ForCollision collection and record IP values and initialurl values to AllMidInfo
	var ips []string
	IPForCollisionExist, err := collectionExists(db_for_collision, *sld+"-ip")
	if IPForCollisionExist {
		collection_for_collision := db_for_collision.Collection(*sld + "-ip")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second) // Set read timeout to 300 seconds
		defer cancel()
		cursor, err := collection_for_collision.Find(ctx, bson.D{})
		if err != nil {
			logger.Error("Error querying collection: ", err) // IP data collection exists, but querying database failed
			return
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var result bson.M
			if err := cursor.Decode(&result); err != nil {
				logger.Error("Error decoding document: ", err) // Decoding failed
				continue
			}
			if ip, ok := result["ip"].(string); ok {
				if ip != "null" {
					ips = append(ips, ip)
				}
			}
		}
		if err := cursor.Err(); err != nil {
			logger.Error("Error iterating over cursor: ", err) // Iteration failed
		}
	} else {
		logger.Info("IPForCollision Not Exist, then read from localfile...")
		ipFilepath := "/home/tianhao/Host_collision-master/ipscan_module/res/" + *sld + "-ip.txt"
		// ipFilepath := "/home/tianhao/Host_collision-master/ipscan_module/res/" + *sld + "-ip.txt"
		ips, err = readFile2Slice(ipFilepath)
		if err != nil {
			logger.Error("IPFile doesn't exist in mongodb; Can't open " + ipFilepath + "!")
			return
		}
		if len(ips) == 1 && ips[0] == "null" {
			ips = []string{} // If there's only one element and it's null, clear the slice
		}
	}
	if !*RecheckInetdm {
		// Check if recheck is needed
		update_info := bson.M{
			"$set": bson.M{
				"ip":         len(ips),
				"normalurls": len(ips) * 2,
			},
		}
		AllMidInfo.UpdateOne(ctx, bson.M{"_id": sld_id}, update_info)
		logger.Info(fmt.Sprintf("Input dataset:\nIPnum:%d\nUrlnum: %d", len(ips), len(ips)*2))
	}

	db := client.Database("hosts-ok-supervisor-1")
	if !*RecheckInetdm {
		// If spv_host file doesn't exist, generate spv_host file and record inethost value, nonhost value, finalhost value to AllMidInfo
		spv_host := *sld + "-host"
		hostExist, _ := collectionExists(db, spv_host)
		host_collection := db.Collection(spv_host)
		if !hostExist {
			var inethosts []string
			var noniphosts []string
			var noniphosts_selected []string

			InetDMForCollisionExist, err := collectionExists(db_for_collision, *sld+"-inetdm")
			if InetDMForCollisionExist {
				collection_for_collision := db_for_collision.Collection(*sld + "-inetdm")
				ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Second) // Set read timeout to 1200 seconds
				defer cancel()
				cursor, err := collection_for_collision.Find(ctx, bson.D{})
				if err != nil {
					logger.Error("Error querying collection: ", err) // inetdm data collection exists, but querying database failed
					return
				}
				defer cursor.Close(ctx)
				for cursor.Next(ctx) {
					var result bson.M
					if err := cursor.Decode(&result); err != nil {
						logger.Error("Error decoding document: ", err) // Decoding failed
						continue
					}
					if hostname, ok := result["domain"].(string); ok {
						inethosts = append(inethosts, hostname)
					}
				}
			} else {
				logger.Info("inetdm Not Exist, then read from localfile...")
				inetdmFilepath := "/home/tianhao/Host_collision-master/hostscan_module/res/" + *sld + "-inetdm.txt"
				inethosts, err = readFile2Slice(inetdmFilepath)
				if err != nil {
					logger.Error("InetMongoDB doesn't exist, and can't open " + inetdmFilepath + "!")
				}
			}

			NondmForCollisionExist, err := collectionExists(db_for_collision, *sld+"-nondm")
			if NondmForCollisionExist {
				collection_for_collision := db_for_collision.Collection(*sld + "-nondm")
				ctx, cancel := context.WithTimeout(context.Background(), 2400*time.Second) // Set read timeout to 2400 seconds
				defer cancel()
				cursor, err := collection_for_collision.Find(ctx, bson.D{})
				if err != nil {
					logger.Error("Error querying collection: ", err) // nondm data collection exists, but querying database failed
					return
				}
				defer cursor.Close(ctx)
				for cursor.Next(ctx) {
					var result bson.M
					if err := cursor.Decode(&result); err != nil {
						logger.Error("Error decoding document: ", err) // Decoding failed
						continue
					}
					if hostname, ok := result["domain"].(string); ok {
						noniphosts = append(noniphosts, hostname)
					}
				}
			} else {
				logger.Info("nondm Not Exist, then read from localfile...")
				nondmFilepath := "/home/tianhao/Host_collision-master/hostscan_module/res/" + *sld + "-nondm.txt"
				noniphosts, err = readFile2Slice(nondmFilepath)
				if err != nil {
					logger.Error("NondmMongoDB doesn't exist, and can't open " + nondmFilepath + "!")
				}
			}

			if sld_id == false {
				insertResult, err := AllMidInfo.InsertOne(ctx, bson.M{
					"sld":    *sld,
					"inetdm": len(inethosts),
					"nondm":  len(noniphosts),
				})
				if err != nil {
					logger.Error("Insert failed: ", err)
					return
				}
				sld_id = insertResult.InsertedID // Get _id of newly inserted record
			} else {
				update_info := bson.M{
					"$set": bson.M{
						"inetdm": len(inethosts),
						"nondm":  len(noniphosts),
					},
				}
				AllMidInfo.UpdateOne(ctx, bson.M{"_id": sld_id}, update_info)
			}
			logger.Info(fmt.Sprintf("inethosts: %d\nnoniphosts: %d", len(inethosts), len(noniphosts)))

			// Grouping temporary dictionary
			tmpDict := make(map[string][]string)
			semaphore := make(chan struct{}, *maxDNSRequests)
			var mu sync.Mutex // Used to protect tmpDict
			var wg sync.WaitGroup
			for _, host := range noniphosts {
				// Populate tmpDict
				if !isValidDomain(host) {
					if *useDNS {
						logger.Warn(host + " ------ Format Error.")
					}
					continue // Only record valid domains
				}

				if *useDNS {
					semaphore <- struct{}{} // Semaphore controls maximum number of running goroutines
					wg.Add(1)
					go func(host string) {
						defer func() {
							<-semaphore
							wg.Done()
						}()
						IsNon, IsInet, IsPub, Error := DomainProperty(host)
						if IsNon { // Only record valid domains and domains that resolve to empty values
							h, ok := getSLD(host, getDMTierNums(*sld)+1)
							if ok {
								mu.Lock() // Lock tmpDict
								tmpDict[h] = append(tmpDict[h], host)
								mu.Unlock() // Unlock tmpDict
							}
						} else if IsInet {
							inethosts = append(inethosts, host)
						} else {
							logger.Info(fmt.Sprintf("%s ------ resolve Exists, then has been deleted. IsNon:%t  IsInet:%t IsPub:%t Error:%v", host, IsNon, IsInet, IsPub, Error))
						}
					}(host)
					wg.Wait()
				} else {
					h, ok := getSLD(host, getDMTierNums(*sld)+1)
					if ok {
						tmpDict[h] = append(tmpDict[h], host)
					} else {
						logger.Println(host + " Can't be found h.")
					}
				}
			}
			// Convert domain slice to insert format
			var documents []interface{}
			for _, hostname := range inethosts {
				documents = append(documents, bson.M{"hostname": hostname, "haschecked": 0, "isinetdm": "true"})
			}

			// Select domains from each SLD
			rand.New(rand.NewSource(time.Now().UnixNano())) // Set random seed
			for _, domains := range tmpDict {
				nums := len(domains)
				if nums > 2 { // Randomly select 2 domains
					selected := sample(domains, 2)
					noniphosts_selected = append(noniphosts_selected, selected...)
				} else { // Add all
					noniphosts_selected = append(noniphosts_selected, domains...)
				}
			}

			// Convert domain slice to insert format
			for _, hostname := range noniphosts_selected {
				documents = append(documents, bson.M{"hostname": hostname, "haschecked": 0, "isinetdm": "false"})
			}
			// Insert multiple documents
			ctx, cancel := context.WithTimeout(context.Background(), 18000*time.Second)
			defer cancel()
			if len(documents) == 0 {
				logger.Error("Document slice is empty. Adding default record.")
				_, err = host_collection.InsertOne(ctx, bson.M{"hostname": "None", "haschecked": 1, "isinetdm": "error"})
				if err != nil {
					logger.Error("InsertOne Fatal IN hosts-ok-supervisor-1." + spv_host)
					logger.Error(err)
					return
				}
			}
			_, err = host_collection.InsertMany(ctx, documents)
			if err != nil {
				logger.Error("Insert Fatal IN hosts-ok-supervisor-1." + spv_host)
				logger.Error(err)
				return
			}
			update_info := bson.M{
				"$set": bson.M{
					"finalhosts": len(noniphosts_selected) + len(inethosts),
				},
			}
			AllMidInfo.UpdateOne(ctx, bson.M{"_id": sld_id}, update_info)
		} else {
			// Check all records in host_collection, add {haschecked: 0} to records without haschecked field
			filter := bson.M{"haschecked": bson.M{"$exists": false}}
			update := bson.M{"$set": bson.M{"haschecked": 0}}
			_, err = host_collection.UpdateMany(ctx, filter, update)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to update records missing haschecked field in host_collection: %v", err))
				return
			}
			logger.Info("Successfully added haschecked: 0 to records missing haschecked field in host_collection")
		}
		// Check if *sld-spv collection exists
		spvCollectionName := *sld + "-spv"
		spvExist, err := collectionExists(db, spvCollectionName)
		if err != nil {
			logger.Error(fmt.Sprintf("Error checking if %s collection exists: %v", spvCollectionName, err))
			return
		}
		if spvExist {
			logger.Info(fmt.Sprintf("%s collection exists", spvCollectionName))
			// Get the host value from the last record in spvCollection
			spvCollection := db.Collection(spvCollectionName)
			// Sort by _id in descending order, get the first record, which is the last record
			findOptions := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
			var spvResult bson.M
			err = spvCollection.FindOne(ctx, bson.M{}, findOptions).Decode(&spvResult)
			if err != nil {
				if err == mongo.ErrNoDocuments {
					logger.Info(fmt.Sprintf("%s collection is empty", spvCollectionName))
				} else {
					logger.Error(fmt.Sprintf("Failed to query last record in %s collection: %v", spvCollectionName, err))
					return
				}
			}
			// Extract host value
			host, ok := spvResult["host"].(string)
			if !ok {
				logger.Error(fmt.Sprintf("No valid host field found in last record of %s collection", spvCollectionName))
				return
			}

			// Locate the record in hostCollection with hostname equal to host, get its _id as <id>
			var hostResult bson.M
			err = host_collection.FindOne(ctx, bson.M{"hostname": host}).Decode(&hostResult)
			if err != nil {
				if err == mongo.ErrNoDocuments {
					logger.Error(fmt.Sprintf("No record with hostname %s found in host_collection", host))
					return
				} else {
					logger.Error(fmt.Sprintf("Failed to query record with hostname %s in host_collection: %v", host, err))
					return
				}
			}

			// Extract _id value
			id, ok := hostResult["_id"]
			if !ok {
				logger.Error("No valid _id field found in host_collection record")
				return
			}

			// Set haschecked value to 1 for all records in hostCollection with _id less than <id>
			filter := bson.M{"_id": bson.M{"$lt": id}}
			update := bson.M{"$set": bson.M{"haschecked": 1}}
			_, err = host_collection.UpdateMany(ctx, filter, update)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to update records with _id less than %v in host_collection: %v", id, err))
				return
			}
			logger.Info(fmt.Sprintf("Successfully set haschecked field to 1 for records with _id less than %v in host_collection", id))
			// Delete spv collection
			err = spvCollection.Drop(ctx)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to delete %s collection: %v", spvCollectionName, err))
				return
			}
			logger.Info(fmt.Sprintf("Successfully deleted %s collection", spvCollectionName))
		}
		// Hosts key-value pairs are (host, _id)
		Hosts := make(map[string]interface{})
		// If host_collection exists, use previous hostname
		ctx, cancel := context.WithTimeout(context.Background(), 18000*time.Second)
		defer cancel()
		// Query all records in natural _id order to ensure consistency with previous host content order
		// Find records with haschecked field equal to 0
		cursor, err := host_collection.Find(ctx, bson.D{{"haschecked", 0}}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
		if err != nil {
			logger.Error(fmt.Sprintf("Find Error IN host_spv ---> %v", err))
			return
		}
		defer cursor.Close(ctx)

		for cursor.Next(ctx) {
			var result bson.M
			if err := cursor.Decode(&result); err != nil {
				logger.Error("Read Error IN host_spv")
				return
			}

			// Extract hostname, _id and isinetdm values and add to dictionary
			if hostname, ok := result["hostname"].(string); ok {
				if id, ok := result["_id"]; ok {
					// Create map containing _id and isinetdm
					hostInfo := map[string]interface{}{
						"_id": id,
					}
					// Add isinetdm field, default to "unknown" if it doesn't exist
					if isinetdm, ok := result["isinetdm"].(string); ok {
						hostInfo["isinetdm"] = isinetdm
					} else {
						hostInfo["isinetdm"] = "unknown"
					}
					Hosts[hostname] = hostInfo
				}
			}
		}
		if err := cursor.Err(); err != nil {
			logger.Error(fmt.Sprintf("Traverse Error IN host_spv ---> %v", err))
			return
		}

		if len(Hosts) == 0 {
			logger.Warn("No hosts to scan, has scanned before OR hosts is empty, stop running.")
			return
		}
		// If ips is empty, set all haschecked fields in Hosts to 1
		if len(ips) == 0 {
			logger.Warn("ips is empty, stop running.")
			ctx, cancel := context.WithTimeout(context.Background(), 18000*time.Second)
			defer cancel()
			db := client.Database("hosts-ok-supervisor-1")
			spv_host := *sld + "-host"
			host_collection := db.Collection(spv_host)
			filter := bson.M{}
			update := bson.M{"$set": bson.M{"haschecked": 1}}
			_, err := host_collection.UpdateMany(ctx, filter, update)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to set all haschecked fields in Hosts to 1: %v", err))
			} else {
				logger.Info("Successfully set all haschecked fields in Hosts to 1")
			}
			return
		}

		if *maxConcurrentRequests == 0 {
			*maxConcurrentRequests = 2 * len(ips)
		}
		processRequests(client, *sld, ips, Hosts, *maxConcurrentRequests, sld_id, *RecheckInetdm)

		// Status code statistics logic
		{
			// Connect to hosts-ok-1 database
			db_ok := client.Database("hosts-ok-1")
			hc_ok_collection := db_ok.Collection(*sld + "-hosts_ok")

			// Build aggregation pipeline to count status codes
			pipeline := mongo.Pipeline{
				{{"$bucket", bson.D{
					{"groupBy", "$status_code"},
					{"boundaries", bson.A{0, 200, 301, 302, 400, 403, 404, 500, 502, 503}},
					{"default", "Other"},
					{"output", bson.D{
						{"count", bson.D{{"$sum", 1}}},
					}},
				}}},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cursor, err := hc_ok_collection.Aggregate(ctx, pipeline)
			if err != nil {
				logger.Error(fmt.Sprintf("Status code statistics failed: %v", err))
				return
			}
			defer cursor.Close(ctx)

			var results []bson.M
			if err = cursor.All(ctx, &results); err != nil {
				logger.Error(fmt.Sprintf("Result parsing failed: %v", err))
				return
			}

			// Build update document
			resultData := bson.M{
				"0":     0,
				"200":   0,
				"301":   0,
				"302":   0,
				"400":   0,
				"403":   0,
				"404":   0,
				"500":   0,
				"502":   0,
				"503":   0,
				"Other": 0,
			}

			for _, result := range results {
				if statusCode, ok := result["_id"].(int32); ok {
					// Handle numeric status codes
					key := fmt.Sprintf("%d", statusCode)
					if _, exists := resultData[key]; exists {
						resultData[key] = result["count"]
					} else {
						// Status codes not in the preset list are counted as Other
						resultData["Other"] = resultData["Other"].(int32) + result["count"].(int32)
					}
				} else {
					// Handle Other category
					logger.Error(fmt.Sprintf("Status code type error (non-numeric value found): %v", result["_id"]))
				}
			}

			// Update AllMidInfo collection
			_, err = AllMidInfo.UpdateOne(
				ctx,
				bson.M{"_id": sld_id},
				bson.M{"$set": bson.M{"Result": resultData}},
			)
			if err != nil {
				logger.Error(fmt.Sprintf("Status code update failed: %v", err))
			}
		}

		logger.Info("\nHostCollision Scan For " + *sld + " Has Finished.")

	} else {
		var inethosts []string

		InetDMForCollisionExist, _ := collectionExists(db_for_collision, *sld+"-inetdm")
		if InetDMForCollisionExist {
			collection_for_collision := db_for_collision.Collection(*sld + "-inetdm")
			ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Second) // Set read timeout to 1200 seconds
			defer cancel()
			cursor, err := collection_for_collision.Find(ctx, bson.D{})
			if err != nil {
				logger.Error("Error querying collection: ", err) // inetdm data collection exists, but querying database failed
				return
			}
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var result bson.M
				if err := cursor.Decode(&result); err != nil {
					logger.Error("Error decoding document: ", err) // Decoding failed
					continue
				}
				if hostname, ok := result["domain"].(string); ok {
					inethosts = append(inethosts, hostname)
				}
			}
		} else {
			logger.Info("inetdm Not Exist...quit...")
			return
		}

		// Build inethosts into map[string]interface{} format
		Hosts := make(map[string]interface{})
		for _, host := range inethosts {
			// Here we simply use host itself as a placeholder value for _id, actual usage should be modified according to business logic
			hostInfo := map[string]interface{}{
				"_id":      host,
				"isinetdm": "true",
			}
			Hosts[host] = hostInfo
		}
		processRequests(client, *sld, ips, Hosts, *maxConcurrentRequests, sld_id, *RecheckInetdm)
	}
}
