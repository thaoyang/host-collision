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

// IP速率限制器结构
type IPRateLimiter struct {
	mu                 sync.Mutex
	lastRequestTime    map[string]time.Time // 每个IP的最后请求时间
	requestCount       map[string]int       // 每个IP的连续请求计数
	pauseUntil         map[string]time.Time // 每个IP的暂停截止时间
	maxRequestsPerIP   int                  // 每个IP的最大连续请求数
	pauseDuration      time.Duration        // 暂停时长
	minRequestInterval time.Duration        // 最小请求间隔（1秒）
}

// 创建新的IP速率限制器
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

// 从URL中提取IP地址
func extractIPFromURL(urlStr string) string {
	// 移除协议前缀 (http:// 或 https://)
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	// 处理IPv6地址 [::1] 格式
	if strings.HasPrefix(urlStr, "[") {
		end := strings.Index(urlStr, "]")
		if end > 0 {
			return urlStr[1:end]
		}
	}

	// 处理IPv4地址或IPv6地址（无括号）
	// 提取IP部分（可能包含端口，但这里我们只需要IP）
	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		ipPart := parts[0]
		// 移除端口号（如果有）
		if colonIdx := strings.LastIndex(ipPart, ":"); colonIdx > 0 {
			// 检查是否是IPv6地址（IPv6地址中可能包含多个冒号）
			if strings.Count(ipPart, ":") > 1 {
				// IPv6地址，不处理
				return ipPart
			}
			// IPv4地址带端口，移除端口
			return ipPart[:colonIdx]
		}
		return ipPart
	}
	return urlStr
}

// 检查是否可以发送请求，如果可以则更新状态
func (rl *IPRateLimiter) CanSendRequest(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// 检查是否在暂停期内
	if pauseTime, exists := rl.pauseUntil[ip]; exists {
		if now.Before(pauseTime) {
			// 仍在暂停期，不能发送
			return false
		}
		// 暂停期已过，清除暂停状态和计数器
		delete(rl.pauseUntil, ip)
		rl.requestCount[ip] = 0
	}

	// 检查请求间隔（每秒最多1个请求）
	if lastTime, exists := rl.lastRequestTime[ip]; exists {
		elapsed := now.Sub(lastTime)
		if elapsed < rl.minRequestInterval {
			// 请求间隔太短，需要等待
			return false
		}
	}

	// 更新请求计数
	rl.requestCount[ip]++

	// 检查是否达到最大请求数
	if rl.requestCount[ip] >= rl.maxRequestsPerIP {
		// 达到限制，设置暂停时间
		rl.pauseUntil[ip] = now.Add(rl.pauseDuration)
		rl.requestCount[ip] = 0 // 重置计数器
		logger.Info(fmt.Sprintf("IP %s reached %d requests, pausing for %v", ip, rl.maxRequestsPerIP, rl.pauseDuration))
	}

	// 更新最后请求时间
	rl.lastRequestTime[ip] = now

	return true
}

// 等待直到可以发送请求
func (rl *IPRateLimiter) WaitUntilCanSend(ip string) {
	for {
		if rl.CanSendRequest(ip) {
			return
		}

		rl.mu.Lock()
		now := time.Now()
		var waitTime time.Duration

		// 计算需要等待的时间
		if pauseTime, exists := rl.pauseUntil[ip]; exists {
			// 在暂停期
			waitTime = pauseTime.Sub(now)
		} else if lastTime, exists := rl.lastRequestTime[ip]; exists {
			// 需要等待请求间隔
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
			// 短暂等待后重试
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

// 判断数据库中某个集合是否存在
func collectionExists(database *mongo.Database, collectionName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // 超时处理机制
	defer cancel()
	collections, err := database.ListCollectionNames(ctx, bson.D{}) // 列出数据库中的集合名称
	if err != nil {
		return false, err
	}
	for _, name := range collections { // 检查目标集合是否在集合列表中
		if name == collectionName {
			return true, nil
		}
	}
	return false, nil
}

// 替换非法 UTF-8 字符为指定字符，例如 "?"
func replaceInvalidUTF8(input string) string {
	valid := make([]rune, 0, len(input))
	for i := 0; i < len(input); {
		r, size := utf8.DecodeRuneInString(input[i:])
		if r == utf8.RuneError && size == 1 {
			valid = append(valid, '?') // 替换非法字符
			i++
		} else {
			valid = append(valid, r)
			i += size
		}
	}
	return string(valid)
}

// 存储结果到MongoDB
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
	// 创建IP速率限制器：每IP每秒最多1个请求，连续10000次后暂停1小时
	ipRateLimiter := NewIPRateLimiter(10000, 1*time.Hour, 1*time.Second)

	// 生成测试数据
	var urls []string
	for _, ip := range ips {
		// 生成https的url
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			fmt.Printf("Skipping invalid IP: %s\n", ip) // 如果IP无效，跳过处理
			continue
		}
		if parsedIP.To4() != nil {
			urls = append(urls, fmt.Sprintf("https://%s", ip)) // IPv4地址
		} else {
			urls = append(urls, fmt.Sprintf("https://[%s]", ip)) // IPv6地址
		}
	}
	for _, ip := range ips {
		// 生成http的url
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			fmt.Printf("Skipping invalid IP: %s\n", ip) // 如果IP无效，跳过处理
			continue
		}
		if parsedIP.To4() != nil {
			urls = append(urls, fmt.Sprintf("http://%s", ip)) // IPv4地址
		} else {
			urls = append(urls, fmt.Sprintf("http://[%s]", ip)) // IPv6地址
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // 读取数据库超时时间设置为600s
	defer cancel()

	semaphore := make(chan struct{}, maxConcurrentRequests) // 信号量，用于控制发送http报文的协程数量

	// 生成对照组
	logger.Info("Processing IPControl...")
	db := client.Database("hosts-ok-ipcontrol-1") // 生成数据库
	ipcontrol_cl_name := sld + "-IPcontrol"
	ipcontrolExist, err := collectionExists(db, ipcontrol_cl_name)
	ipcontrol_collection := db.Collection(ipcontrol_cl_name) // 待写入&读取的数据库集合
	if !ipcontrolExist {
		// 如果不存在，再获取对照组数据，并写入对照组数据库
		var wg3 sync.WaitGroup // 消费者协程控制
		var wg4 sync.WaitGroup // 生产者协程控制
		ipResults := make(chan *Response, maxConcurrentRequests)

		wg3.Add(1)
		go func() {
			defer wg3.Done()
			for res := range ipResults {
				storeResultsToMongoDB(res, ipcontrol_collection, false)
			}
		}()

		for _, host := range []string{sld, "", "xxxyyyzzz." + sld, "A123.123-b.c-123." + sld} { // 作为生产者，发送http请求写入通道，通过信号量控制协程最大并发数量
			for _, url := range urls { // 对照组由四次http请求结构组成：host为sld,不带host，两个大概率不存在的子域名
				wg4.Add(1)
				semaphore <- struct{}{} // 信号量控制最多运行的协程数
				go func(url string, host string) {
					defer func() {
						<-semaphore
						wg4.Done()
					}() // release semaphore

					// 提取IP并应用速率限制
					ip := extractIPFromURL(url)
					ipRateLimiter.WaitUntilCanSend(ip)

					var finalRes *Response
					// 尝试5次请求，每次中间会有一次重试，所以最多尝试10次
					for i := 0; i < 5; i++ {
						// 每次重试前也要检查速率限制
						if i > 0 {
							ipRateLimiter.WaitUntilCanSend(ip)
						}
						res := getPageContent(url, host)
						if res.StatusCode != 0 {
							finalRes = res
							break
						}
						// 记录最后一次请求结果
						if i == 4 {
							finalRes = res
						}
						// 如果不是最后一次请求，等待1秒
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
		close(ipResults) // 关闭通道保证消费者读取通道完成后不再阻塞直接退出
		wg3.Wait()
		logger.Info("IPControl has generated successfully!")
	}
	logger.Info("Reading IPControl and Initializing inputs...")
	cursor, err := ipcontrol_collection.Find(ctx, bson.M{}) // 查询所有记录
	if err != nil {
		log.Fatalf("查询失败: %v", err)
	}
	defer cursor.Close(ctx)
	type ctrolRecord struct { // 定义查询结构体
		Statuscode int
		Title      string
		Patchdata  string
	}
	urlMap := make(map[string][]ctrolRecord) // 初始化 map
	for cursor.Next(ctx) {
		// 遍历查询结果
		var result struct {
			URL        string `bson:"url"`
			Statuscode int    `bson:"status_code"`
			Title      string `bson:"title"`
			Patchdata  string `bson:"patchdata"`
		}

		if err := cursor.Decode(&result); err != nil {
			log.Fatalf("解码记录失败: %v", err)
		}

		if result.Statuscode == 0 {
			continue
		}

		urlMap[result.URL] = append(urlMap[result.URL], ctrolRecord{ // 将新记录存入urlMap
			Statuscode: result.Statuscode,
			Title:      result.Title,
			Patchdata:  result.Patchdata,
		})
	}

	// HC测试
	urls = []string{} // 提取所有键（URL）并存储在切片中，从而更新url切片，从而排除超时不可达的ip
	for url := range urlMap {
		urls = append(urls, url)
	}
	if err := cursor.Err(); err != nil {
		log.Fatalf("遍历记录失败: %v", err)
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
	var wg1 sync.WaitGroup // 消费者协程控制
	var wg2 sync.WaitGroup // 生产者协程控制
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

	for host, hostInfo := range Hosts { // 作为生产者，对Hosts进行迭代查询，发送http请求写入通道，通过信号量控制协程最大并发数量
		// 类型断言获取isinetdm值
		info, ok := hostInfo.(map[string]interface{})
		if !ok {
			continue
		}
		isinetdm, ok := info["isinetdm"].(string)
		if !ok {
			isinetdm = "false" // 默认值
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

				// 提取IP并应用速率限制
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
			// 查找 _id 为 Host[host] 的值对应的文档，并更新其 "haschecked" 字段为 1
			filter := bson.D{{"_id", id}}
			update := bson.D{{"$set", bson.D{{"haschecked", 1}}}}
			_, err := host_collection.UpdateOne(context.TODO(), filter, update)
			if err != nil {
				logger.Error("Error updating 'haschecked' field in MongoDB: ", err)
			}
		}
	}
	wg2.Wait()
	close(hcResults) // 关闭通道保证消费者读取通道完成后不再阻塞直接退出
	wg1.Wait()
}

// 获取title内容
func getTitle(body string) string {
	re := regexp.MustCompile(`<title>([\s\S]*?)</title>`)
	match := re.FindStringSubmatch(body)
	if match != nil && len(match) > 1 {
		return strings.TrimSpace(match[1])
	} else {
		return ""
	}
}

// 发起http请求，增加请求头Host
func getPageContent(urlStr string, hostName string) *Response {
	//display 'Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>' error
	log.SetOutput(io.Discard)

	//display "ERROR RESTY" error
	logger := logrus.New()
	logger.Out = io.Discard

	client := resty.New().SetLogger(logger)
	//忽略证书错误
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	//设置超时时间
	client.SetTimeout(time.Duration(3 * time.Second)) //超时时间设置为3s
	//设置请求头
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
	//取消自动跳转
	client.SetRedirectPolicy(resty.NoRedirectPolicy())
	//GET请求结束时，立即断开TCP连接，降低服务器负载
	client.SetCloseConnection(true)

	//重试1次，中间间隔2s
	client.SetRetryCount(1).SetRetryWaitTime(2 * time.Second).SetRetryMaxWaitTime(3 * time.Second)

	//发起http请求
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
			// 收集错误响应的头信息
			headers := make(bson.M)
			for k, v := range resp.Header() {
				headers[k] = v
			}
			if statusCode > 300 && statusCode < 400 {
				if locations, exists := resp.RawResponse.Header["Location"]; exists && len(locations) > 0 {
					// 获取 Location 字段的第一个值
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
		//读取http响应内容
		body := resp.String()
		title := getTitle(body)
		lenPage := len(body)
		//截取返回内容，避免内容过大占用内存
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

	file, err := os.Open(filepath) // 打开文件
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return nil, err
	}
	defer file.Close()

	var lines []string // 创建一个切片保存文件内容

	scanner := bufio.NewScanner(file) // 使用 bufio.Scanner 按行读取文件内容
	for scanner.Scan() {
		if scanner.Text() != "" { // 排除空字符串
			lines = append(lines, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil { // 检查读取过程中是否有错误
		fmt.Printf("Error reading file: %v\n", err)
		return nil, err
	}
	return lines, nil
}

// 计算域名层级数量
func getDMTierNums(hostname string) int {
	// 移除末尾的点（如果有）
	if strings.HasSuffix(hostname, ".") {
		hostname = strings.TrimSuffix(hostname, ".")
	}
	// 按 "." 分割并返回分割后的数量
	return len(strings.Split(hostname, "."))
}

// 获取域名的第 numth 部分（从右往左）
func getSLD(domain string, numth int) (string, bool) {
	// 移除末尾的点
	domain = strings.TrimSuffix(domain, ".")
	// 按 "." 分割域名
	domainParts := strings.Split(domain, ".")
	// 如果域名部分的数量不足 numth，返回 false
	if len(domainParts) < numth {
		return "", false
	}
	return domainParts[len(domainParts)-numth], true
}

// 随机抽样函数
func sample(slice []string, n int) []string {
	if n >= len(slice) {
		return slice
	}

	// 创建一个局部随机数生成器
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// 打乱切片内容
	r.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})

	// 返回前 n 个元素
	return slice[:n]
}

func isValidDomain(domain string) bool {
	// 域名的正则表达式
	// 匹配：有效域名如 example.com、sub.domain.org、xn--fiq228c.com 等
	domainRegex := `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(domainRegex, domain)
	return matched
}

// 判断是否为公网地址
func isPublicIP(ipAddress string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		fmt.Printf("Invalid IP address: %s\n", ipAddress)
		return false
	}

	// 私有地址范围
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // CGNAT 范围
	}

	// 链路本地地址和多播地址范围
	reservedCIDRs := []string{
		"169.254.0.0/16", // 链路本地地址
		"224.0.0.0/4",    // 多播地址
		"240.0.0.0/4",    // 保留地址
		"::1/128",        // IPv6 回环地址
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 链路本地地址
		"ff00::/8",       // IPv6 多播地址
	}

	// 检查是否为回环地址
	if ip.IsLoopback() {
		return false
	}

	// 检查是否为私有地址或保留地址
	for _, cidr := range append(privateCIDRs, reservedCIDRs...) {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return false
		}
	}

	// 如果不是上述范围，则为公网地址
	return true
}

func DomainProperty(domain string) (IsNon bool, IsInet bool, IsPub bool, Error error) {
	// 创建两个分别请求 IPv4 和 IPv6 的 DNS 消息
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)

	// 设置 DNS 客户端
	client := &dns.Client{
		Timeout: 2 * time.Second, // 设置超时时间为 2 秒
	}
	// 使用指定的 DNS 服务器
	dnsServer := "114.114.114.114:53"
	Error = nil

	// 执行查询 IPv4
	IsInet_A, IsNon_A := false, false
	responseA, _, err := client.Exchange(msgA, dnsServer)
	if err == nil {
		if len(responseA.Answer) == 0 { // 检查响应的答案部分是否为空
			IsNon_A = true
		} else {
			canary := true // canary用于排除len()>0但并不是ipv4的情况
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

	// 执行查询 IPv6
	IsInet_AAAA, IsNon_AAAA := false, false
	responseAAAA, _, err := client.Exchange(msgAAAA, dnsServer)
	if err == nil {
		if len(responseAAAA.Answer) == 0 { // 检查响应的答案部分是否为空
			IsNon_AAAA = true
		} else {
			canary := true // canary用于排除len()>0但并不是ipv4的情况
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

	flag.Parse() // 解析命令行标志

	if *sld == "" {
		logger.Error("Parameter --sld Must be inputted!")
		return // 缺少返回语句，添加后当参数缺失时程序退出
	}

	// 连接数据库
	clientOptions := options.Client().ApplyURI("mongodb://HostCollision:H0stC0111s10n@202.112.47.70:27017") // 作为消费者，读取通道并且写入数据库
	client, err := mongo.Connect(context.TODO(), clientOptions)                                             // 连接到 MongoDB
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	err = client.Ping(context.TODO(), nil) // 确保连接成功
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}
	defer client.Disconnect(context.TODO()) // 关闭连接
	logger.Info("Successfully connected to MongoDB")

	// 确定AllMidInfo中要写入的sld的_id值
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
		// 保持 sld_id 为 false
	} else {
		logger.Error(fmt.Sprintf("查询失败: %v", err))
		return
	}

	// 从ForCollision的集合中读取IPs，并记录IP值和intialurl值到AllMidInfo；
	var ips []string
	IPForCollisionExist, err := collectionExists(db_for_collision, *sld+"-ip")
	if IPForCollisionExist {
		collection_for_collision := db_for_collision.Collection(*sld + "-ip")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second) // 设置读取超时时间为300秒
		defer cancel()
		cursor, err := collection_for_collision.Find(ctx, bson.D{})
		if err != nil {
			logger.Error("Error querying collection: ", err) // ip数据集合存在，但查询数据库失败
			return
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var result bson.M
			if err := cursor.Decode(&result); err != nil {
				logger.Error("Error decoding document: ", err) // 解码失败
				continue
			}
			if ip, ok := result["ip"].(string); ok {
				if ip != "null" {
					ips = append(ips, ip)
				}
			}
		}
		if err := cursor.Err(); err != nil {
			logger.Error("Error iterating over cursor: ", err) // 遍历失败
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
			ips = []string{} // 如果只有一个元素且为null，则清空切片
		}
	}
	if !*RecheckInetdm {
		// 检查是否需要重新检查
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
		// 如果spv_host文件不存在。生成spv_host文件，并记录inethost值\nonhost值\finalhost值到AllMidInfo；
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
				ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Second) // 设置读取超时时间为1200秒
				defer cancel()
				cursor, err := collection_for_collision.Find(ctx, bson.D{})
				if err != nil {
					logger.Error("Error querying collection: ", err) //  inetdm数据集合存在，但查询数据库失败
					return
				}
				defer cursor.Close(ctx)
				for cursor.Next(ctx) {
					var result bson.M
					if err := cursor.Decode(&result); err != nil {
						logger.Error("Error decoding document: ", err) // 解码失败
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
				ctx, cancel := context.WithTimeout(context.Background(), 2400*time.Second) // 设置读取超时时间为2400秒
				defer cancel()
				cursor, err := collection_for_collision.Find(ctx, bson.D{})
				if err != nil {
					logger.Error("Error querying collection: ", err) //  nondm数据集合存在，但查询数据库失败
					return
				}
				defer cursor.Close(ctx)
				for cursor.Next(ctx) {
					var result bson.M
					if err := cursor.Decode(&result); err != nil {
						logger.Error("Error decoding document: ", err) // 解码失败
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
					logger.Error("插入失败: ", err)
					return
				}
				sld_id = insertResult.InsertedID // 获取新插入记录的_id
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

			// 分组临时字典
			tmpDict := make(map[string][]string)
			semaphore := make(chan struct{}, *maxDNSRequests)
			var mu sync.Mutex // 用于保护 tmpDict
			var wg sync.WaitGroup
			for _, host := range noniphosts {
				// 填充 tmpDict
				if !isValidDomain(host) {
					if *useDNS {
						logger.Warn(host + " ------ Format Error.")
					}
					continue // 只记录有效域名
				}

				if *useDNS {
					semaphore <- struct{}{} // 信号量控制最多运行的协程数
					wg.Add(1)
					go func(host string) {
						defer func() {
							<-semaphore
							wg.Done()
						}()
						IsNon, IsInet, IsPub, Error := DomainProperty(host)
						if IsNon { // 只记录有效域名和解析为空值的域名
							h, ok := getSLD(host, getDMTierNums(*sld)+1)
							if ok {
								mu.Lock() // 锁定 tmpDict
								tmpDict[h] = append(tmpDict[h], host)
								mu.Unlock() // 解锁 tmpDict
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
			// 将域名切片转换为插入格式
			var documents []interface{}
			for _, hostname := range inethosts {
				documents = append(documents, bson.M{"hostname": hostname, "haschecked": 0, "isinetdm": "true"})
			}

			// 从每个 SLD 中选择域名
			rand.New(rand.NewSource(time.Now().UnixNano())) // 设置随机数种子
			for _, domains := range tmpDict {
				nums := len(domains)
				if nums > 2 { // 随机选取 2 个域名
					selected := sample(domains, 2)
					noniphosts_selected = append(noniphosts_selected, selected...)
				} else { // 全部加入
					noniphosts_selected = append(noniphosts_selected, domains...)
				}
			}

			// 将域名切片转换为插入格式
			for _, hostname := range noniphosts_selected {
				documents = append(documents, bson.M{"hostname": hostname, "haschecked": 0, "isinetdm": "false"})
			}
			// 插入多个文档
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
			// 检查 host_collection 的所有记录，没有 haschecked 字段的记录添加 {haschecked: 0}
			filter := bson.M{"haschecked": bson.M{"$exists": false}}
			update := bson.M{"$set": bson.M{"haschecked": 0}}
			_, err = host_collection.UpdateMany(ctx, filter, update)
			if err != nil {
				logger.Error(fmt.Sprintf("更新 host_collection 中缺少 haschecked 字段的记录失败: %v", err))
				return
			}
			logger.Info("成功为 host_collection 中缺少 haschecked 字段的记录添加 haschecked: 0")
		}
		// 判断 *sld-spv 集合是否存在
		spvCollectionName := *sld + "-spv"
		spvExist, err := collectionExists(db, spvCollectionName)
		if err != nil {
			logger.Error(fmt.Sprintf("检查 %s 集合是否存在时出错: %v", spvCollectionName, err))
			return
		}
		if spvExist {
			logger.Info(fmt.Sprintf("%s 集合存在", spvCollectionName))
			// 取 spvCollection 的最后一条记录的 host 值
			spvCollection := db.Collection(spvCollectionName)
			// 按 _id 降序排序，取第一条记录，即最后一条记录
			findOptions := options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}})
			var spvResult bson.M
			err = spvCollection.FindOne(ctx, bson.M{}, findOptions).Decode(&spvResult)
			if err != nil {
				if err == mongo.ErrNoDocuments {
					logger.Info(fmt.Sprintf("%s 集合为空", spvCollectionName))
				} else {
					logger.Error(fmt.Sprintf("查询 %s 集合最后一条记录失败: %v", spvCollectionName, err))
					return
				}
			}
			// 提取 host 值
			host, ok := spvResult["host"].(string)
			if !ok {
				logger.Error(fmt.Sprintf("%s 集合最后一条记录中未找到有效的 host 字段", spvCollectionName))
				return
			}

			// 定位到 hostCollection 的 hostname 为 host 的 _id 为 <id>
			var hostResult bson.M
			err = host_collection.FindOne(ctx, bson.M{"hostname": host}).Decode(&hostResult)
			if err != nil {
				if err == mongo.ErrNoDocuments {
					logger.Error(fmt.Sprintf("host_collection 中未找到 hostname 为 %s 的记录", host))
					return
				} else {
					logger.Error(fmt.Sprintf("查询 host_collection 中 hostname 为 %s 的记录失败: %v", host, err))
					return
				}
			}

			// 提取 _id 值
			id, ok := hostResult["_id"]
			if !ok {
				logger.Error("host_collection 记录中未找到有效的 _id 字段")
				return
			}

			// 将 hostCollection 所有 _id 小于 <id> 的记录的 haschecked 的值都设置为 1
			filter := bson.M{"_id": bson.M{"$lt": id}}
			update := bson.M{"$set": bson.M{"haschecked": 1}}
			_, err = host_collection.UpdateMany(ctx, filter, update)
			if err != nil {
				logger.Error(fmt.Sprintf("更新 host_collection 中 _id 小于 %v 的记录失败: %v", id, err))
				return
			}
			logger.Info(fmt.Sprintf("成功将 host_collection 中 _id 小于 %v 的记录的 haschecked 字段设置为 1", id))
			// 删除 spv 集合
			err = spvCollection.Drop(ctx)
			if err != nil {
				logger.Error(fmt.Sprintf("删除 %s 集合失败: %v", spvCollectionName, err))
				return
			}
			logger.Info(fmt.Sprintf("成功删除 %s 集合", spvCollectionName))
		}
		// Hosts的键值对为（host, _id）
		Hosts := make(map[string]interface{})
		// host_collection存在，就使用之前的hostname
		ctx, cancel := context.WithTimeout(context.Background(), 18000*time.Second)
		defer cancel()
		// 按 `_id` 自然顺序查询所有记录，保证和先前的host内容顺序一致
		// 查找 haschecked 字段为 0 的记录
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

			// 提取域名、_id和isinetdm值并加入字典
			if hostname, ok := result["hostname"].(string); ok {
				if id, ok := result["_id"]; ok {
					// 创建包含_id和isinetdm的map
					hostInfo := map[string]interface{}{
						"_id": id,
					}
					// 添加isinetdm字段，默认为"unknown"如果不存在
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
		// 如果 ips 为空，将 Hosts 的所有 haschecked 字段设置为 1
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
				logger.Error(fmt.Sprintf("将 Hosts 的所有 haschecked 字段设置为 1 失败: %v", err))
			} else {
				logger.Info("成功将 Hosts 的所有 haschecked 字段设置为 1")
			}
			return
		}

		if *maxConcurrentRequests == 0 {
			*maxConcurrentRequests = 2 * len(ips)
		}
		processRequests(client, *sld, ips, Hosts, *maxConcurrentRequests, sld_id, *RecheckInetdm)

		// 状态码统计逻辑
		{
			// 连接到 hosts-ok-1 数据库
			db_ok := client.Database("hosts-ok-1")
			hc_ok_collection := db_ok.Collection(*sld + "-hosts_ok")

			// 构建聚合管道统计状态码
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
				logger.Error(fmt.Sprintf("状态码统计失败: %v", err))
				return
			}
			defer cursor.Close(ctx)

			var results []bson.M
			if err = cursor.All(ctx, &results); err != nil {
				logger.Error(fmt.Sprintf("结果解析失败: %v", err))
				return
			}

			// 构建更新文档
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
					// 处理数字型状态码
					key := fmt.Sprintf("%d", statusCode)
					if _, exists := resultData[key]; exists {
						resultData[key] = result["count"]
					} else {
						// 不在预设列表中的状态码计入 Other
						resultData["Other"] = resultData["Other"].(int32) + result["count"].(int32)
					}
				} else {
					// 处理 Other 分类
					logger.Error(fmt.Sprintf("状态码类型错误（出现不为数字的值）: %v", result["_id"]))
				}
			}

			// 更新 AllMidInfo 集合
			_, err = AllMidInfo.UpdateOne(
				ctx,
				bson.M{"_id": sld_id},
				bson.M{"$set": bson.M{"Result": resultData}},
			)
			if err != nil {
				logger.Error(fmt.Sprintf("状态码更新失败: %v", err))
			}
		}

		logger.Info("\nHostCollision Scan For " + *sld + " Has Finished.")

	} else {
		var inethosts []string

		InetDMForCollisionExist, _ := collectionExists(db_for_collision, *sld+"-inetdm")
		if InetDMForCollisionExist {
			collection_for_collision := db_for_collision.Collection(*sld + "-inetdm")
			ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Second) // 设置读取超时时间为1200秒
			defer cancel()
			cursor, err := collection_for_collision.Find(ctx, bson.D{})
			if err != nil {
				logger.Error("Error querying collection: ", err) //  inetdm数据集合存在，但查询数据库失败
				return
			}
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var result bson.M
				if err := cursor.Decode(&result); err != nil {
					logger.Error("Error decoding document: ", err) // 解码失败
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

		// 将 inethosts 构建成 map[string]interface{} 格式
		Hosts := make(map[string]interface{})
		for _, host := range inethosts {
			// 这里简单用 host 自身作为 _id 的占位值，实际使用时需要根据业务逻辑修改
			hostInfo := map[string]interface{}{
				"_id":      host,
				"isinetdm": "true",
			}
			Hosts[host] = hostInfo
		}
		processRequests(client, *sld, ips, Hosts, *maxConcurrentRequests, sld_id, *RecheckInetdm)
	}
}
