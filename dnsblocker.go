package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("dnsblocker")
var logFormatter = logging.MustStringFormatter(
	"%{color}%{time} [%{level:.5s}] %{message}%{color:reset}",
)

var dnsServer string
var listen string
var hostsPath string
var logLevelStr string
var blocked = []string{}
var cacheSize int
var cacheDuration int
var cache *freecache.Cache

func init() {
	flag.StringVar(&dnsServer, "dns-server", "192.168.1.1:domain",
		"DNS server for proxy not blocked queries")
	flag.StringVar(&listen, "listen", ":domain", "Listen is pair 'ip:port'")
	flag.StringVar(&hostsPath, "hosts-path", "hosts", "Path to hosts file")
	flag.StringVar(&logLevelStr, "log-level", "INFO", "Set minimum log level")
	flag.IntVar(&cacheSize, "cache-size", 1024*1024, "Set cache size into bytes")
	flag.IntVar(&cacheDuration, "cache-duration", 5*60, "Set cache duration into seconds")
	flag.Parse()

	configureLogger()
	configureCache()

	logger.Infof("Start listen on: %s", listen)
	logger.Infof("DNS source: %s", dnsServer)
	logger.Infof("Hosts file: %s", hostsPath)
	logger.Infof("Log level: %s", logLevelStr)
	logger.Infof("Cache size: %d", cacheSize)
	logger.Infof("Cache duration: %d", cacheDuration)

	loadBlocked()
}

func configureLogger() {
	logging.SetBackend(
		logging.MultiLogger(
			logging.NewBackendFormatter(
				logging.NewLogBackend(os.Stdout, "", 0),
				logFormatter,
			),
		),
	)
	normalizedLogLevel := strings.ToUpper(logLevelStr)
	if logLevel, levelErr := logging.LogLevel(normalizedLogLevel); nil == levelErr {
		logging.SetLevel(logLevel, "")
	} else {
		logger.Fatal(levelErr)
	}
}

func loadBlocked() {
	file, openErr := os.Open(hostsPath)
	if nil != openErr {
		panic(openErr)
	}
	defer file.Close()
	buffer := bufio.NewReader(file)
	for {
		line, readErr := buffer.ReadString('\n')
		if readErr == io.EOF {
			break
		} else if nil != readErr {
			panic(readErr)
		}

		host := dns.Fqdn(line[0 : len(line)-1])
		blocked = append(blocked, host)
	}
	logger.Infof("Loaded %d domains", len(blocked))
}

func configureCache() {
	cache = freecache.NewCache(cacheSize)
}

func isBlocked(requestedName string) bool {
	for _, name := range blocked {
		if dns.IsSubDomain(name, requestedName) {
			return true
		}
	}
	return false
}

func messageCacheKey(message *dns.Msg) string {
	questions := make([]string, 0, len(message.Question))
	for _, question := range message.Question {
		questionRow := fmt.Sprintf("%s %s %s", question.Name,
			dns.ClassToString[question.Qclass], dns.TypeToString[question.Qtype])

		questions = append(questions, questionRow)
	}
	return strings.Join(questions, ",")
}

func fetchCache(cacheKey string) (*dns.Msg, error) {
	messageData, cacheErr := cache.Get([]byte(cacheKey))
	if freecache.ErrNotFound == cacheErr {
		logger.Infof("Message for key %s not found in cache", cacheKey)
		return nil, cacheErr
	}
	if nil != cacheErr {
		logger.Errorf("Cache error for key %s: %s", cacheKey, cacheErr)
		return nil, cacheErr
	}

	logger.Infof("Message for key %s found in cache", cacheKey)

	dnsMessage := new(dns.Msg)
	if unpackErr := dnsMessage.Unpack(messageData); nil != unpackErr {
		logger.Errorf("Error unpack mesasge with key %s: %s", cacheKey, unpackErr)
		return nil, unpackErr
	}

	logger.Debug("Success unpack message")
	return dnsMessage, nil
}

func writeCache(cacheKey string, dnsMessage *dns.Msg) error {
	messageData, packErr := dnsMessage.Pack()
	if nil != packErr {
		logger.Errorf("Error pack message with key %s: %s", cacheKey, packErr)
		return packErr
	}

	logger.Debugf("Pack message with key %s is success", cacheKey)

	if cacheErr := cache.Set([]byte(cacheKey), messageData, cacheDuration); nil != cacheErr {
		logger.Errorf("Error write cache for key %s: %s", cacheKey, cacheErr)
		return cacheErr
	}
	logger.Debugf("Write cache for key %s is success", cacheKey)
	return nil
}

func dnsExchangeWithCache(requestMessage *dns.Msg) (*dns.Msg, error) {
	cacheKey := messageCacheKey(requestMessage)

	if cachedResponseMessage, fetchErr := fetchCache(cacheKey); nil == fetchErr {
		cachedResponseMessage.SetReply(requestMessage)
		return cachedResponseMessage, nil
	} else if freecache.ErrNotFound != fetchErr {
		return nil, fetchErr
	}

	responseMessage, exchangeErr := dns.Exchange(requestMessage, dnsServer)
	if nil != exchangeErr {
		logger.Errorf("Exchange error for key %s: %s", cacheKey, exchangeErr)
		return nil, exchangeErr
	}

	logger.Debugf("Exchange for key %s is success", cacheKey)

	if writeErr := writeCache(cacheKey, responseMessage); nil != writeErr {
		return nil, writeErr
	}

	return responseMessage, nil
}

func proxyRequest(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	responseMessage, fetchErr := dnsExchangeWithCache(requestMessage)

	if nil == fetchErr {
		logger.Debug("Response message: %+v", responseMessage)
		writeResponse(writer, responseMessage)
	} else {
		logger.Errorf("Fetch error: %s", fetchErr)

		errorMessage := new(dns.Msg)
		errorMessage.SetRcode(requestMessage, dns.RcodeServerFailure)
		logger.Errorf("Error message: %+v", errorMessage)

		writeResponse(writer, errorMessage)
	}
}

func errorResponse(writer dns.ResponseWriter, requestMessage *dns.Msg, responseCode int) {
	responseMessage := new(dns.Msg)
	responseMessage.SetRcode(requestMessage, responseCode)
	logger.Debugf("Block response: %+v", responseMessage)
	writeResponse(writer, responseMessage)
}

func handler(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	logger.Debugf("Query message: %+v", requestMessage)
	logger.Infof("Accept request from %v", writer.RemoteAddr())

	if 1 != len(requestMessage.Question) {
		logger.Warning("Can not process message with multiple questions")
		errorResponse(writer, requestMessage, dns.RcodeFormatError)
		return
	}

	question := requestMessage.Question[0]
	logger.Infof("Request name: %s", question.Name)

	if isBlocked(question.Name) {
		logger.Infof("Block name: %s", question.Name)
		errorResponse(writer, requestMessage, dns.RcodeRefused)
	} else {
		logger.Infof("Request name %s is proxed", question.Name)
		proxyRequest(writer, requestMessage)
	}
}

func writeResponse(writer dns.ResponseWriter, message *dns.Msg) {
	if writeErr := writer.WriteMsg(message); nil == writeErr {
		logger.Debug("Writer success")
	} else {
		logger.Errorf("Writer error: %s", writeErr)
	}
}

func main() {
	server := &dns.Server{
		Addr:    listen,
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	if serverErr := server.ListenAndServe(); nil != serverErr {
		logger.Fatal(serverErr)
	}
}
