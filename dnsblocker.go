package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("dnsblocker")
var logFormatter = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} [%{level:.5s}] %{message}%{color:reset}",
)

var dnsServer string
var listen string
var hostsPath string
var logLevelStr string
var blocked = []string{}

func init() {
	flag.StringVar(&dnsServer, "dns-server", "192.168.1.1:domain",
		"DNS server for proxy not blocked queries")
	flag.StringVar(&listen, "listen", ":domain", "Listen is pair 'ip:port'")
	flag.StringVar(&hostsPath, "hosts-path", "hosts", "Path to hosts file")
	flag.StringVar(&logLevelStr, "log-level", "INFO", "Set minimum log level")
	flag.Parse()

	configureLogger()

	logger.Infof("Start with: listen: %s; dns-server: %s; hosts-path: %s",
		listen, dnsServer, hostsPath)

	loadBlocked()
}

func configureLogger() {
	logging.SetFormatter(logFormatter)
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

func isBlocked(requestedName string) bool {
	for _, name := range blocked {
		if name == requestedName {
			return true
		}
	}
	return false
}

func proxyRequest(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	responseMessage, exchangeErr := dns.Exchange(requestMessage, dnsServer)

	if nil == exchangeErr {
		logger.Debug("Response message: %+v", responseMessage)
		writeResponse(writer, responseMessage)
	} else {
		logger.Errorf("Exchange error: %s", exchangeErr)

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
