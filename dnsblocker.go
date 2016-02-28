package main

import (
	"bufio"
	"flag"
	"io"
	"os"

	"github.com/miekg/dns"
	"github.com/op/go-logging"
)

var logger = formatedLogger()

var dnsServer string
var listen string
var hostsPath string
var blocked = []string{}

func init() {
	flag.StringVar(&dnsServer, "dns-server", "192.168.1.1:domain",
		"DNS server for proxy not blocked queries")
	flag.StringVar(&listen, "listen", ":domain", "Listen is pair 'ip:port'")
	flag.StringVar(&hostsPath, "hosts-path", "hosts", "Path to hosts file")
	flag.Parse()

	logger.Infof("Start with: listen: %s; dns-server: %s; hosts-path: %s",
		listen, dnsServer, hostsPath)

	loadBlocked()
}

func formatedLogger() *logging.Logger {
	logger := logging.MustGetLogger("dnsblocker")
	logger.SetBackend(
		logging.MultiLogger(
			logging.NewBackendFormatter(
				logging.NewLogBackend(os.Stdout, "", 0),
				logging.MustStringFormatter(
					"%{color}%{time:15:04:05.000} [%{level:.5s}] %{message}%{color:reset}",
				),
			),
		),
	)
	return logger
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

		host := line[0 : len(line)-1]
		blocked = append(blocked, host)
	}
	logger.Infof("Loaded %d domains", len(blocked))
}

func isBlocked(requestMesage *dns.Msg) bool {
	if 1 != len(requestMesage.Question) {
		logger.Warning("Can not process message with multiple questions")
		return false
	}

	question := requestMesage.Question[0]
	for _, name := range blocked {
		if dns.Fqdn(name) == question.Name {
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

func blockedRequest(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	responseMessage := new(dns.Msg)
	responseMessage.SetRcode(requestMessage, dns.RcodeRefused)
	logger.Debugf("Block response: %+v", responseMessage)
	writeResponse(writer, responseMessage)
}

func handler(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	logger.Debugf("Query message: %+v", requestMessage)

	if isBlocked(requestMessage) {
		blockedRequest(writer, requestMessage)
	} else {
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
