package main

import (
	"bufio"
	"flag"
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

	logger.Infof("Start with: listen: %s; dns-server: %s; hosts-path: %s",
		listen, dnsServer, hostsPath)

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

func messageCacheKey(message *dns.Msg) []byte {
	questions := make([]string, 0, len(message.Question))
	for _, question := range message.Question {
		questions = append(questions, question.String())
	}
	return ([]byte)(strings.Join(questions, "\n"))
}

func dnsExchangeWithCache(requestMessage *dns.Msg) (*dns.Msg, error) {
	cacheKey := messageCacheKey(requestMessage)

	if cachedResponseData, cacheGetErr := cache.Get(cacheKey); nil == cacheGetErr {
		logger.Info("Message found in cache")
		cachedResponseMessage := new(dns.Msg)
		if unpackErr := cachedResponseMessage.Unpack(cachedResponseData); nil != unpackErr {
			logger.Errorf("Unpack error: %s", unpackErr)
			return nil, unpackErr
		}
		logger.Debug("Success unpack message")
		cachedResponseMessage.SetReply(requestMessage)
		return cachedResponseMessage, nil
	} else if freecache.ErrNotFound == cacheGetErr {
		logger.Infof("Message not found in cache: %s", cacheGetErr)
		responseMessage, exchangeErr := dns.Exchange(requestMessage, dnsServer)
		if nil != exchangeErr {
			logger.Errorf("Exchange error: %s", exchangeErr)
			return nil, exchangeErr
		}
		logger.Debug("Exchange success")
		responseData, packErr := responseMessage.Pack()
		if nil != packErr {
			logger.Errorf("Error pack message: %s", packErr)
			return nil, packErr
		}
		logger.Debug("Pack success")
		if cacheSetErr := cache.Set(cacheKey, responseData, cacheDuration); nil != cacheSetErr {
			logger.Error("Error set cache")
			return nil, cacheSetErr
		}
		logger.Debug("Write cache success")
		return responseMessage, nil
	} else {
		logger.Errorf("Cache error: %s", cacheGetErr)
		return nil, cacheGetErr
	}
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
