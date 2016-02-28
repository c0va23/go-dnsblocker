package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"

	"github.com/miekg/dns"
)

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

	log.Printf("Start with: listen: %s; dns-server: %s; hosts-path: %s\n",
		listen, dnsServer, hostsPath)

	loadBlocked()
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
	log.Printf("Loaded %d domains", len(blocked))
}

func isBlocked(requestMesage *dns.Msg) bool {
	if 1 != len(requestMesage.Question) {
		log.Printf("Can not process message with multiple questions")
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
		log.Printf("Response message: %+v\n", responseMessage)
		writeResponse(writer, responseMessage)
	} else {
		log.Printf("Exchange error: %s\n", exchangeErr)

		errorMessage := new(dns.Msg)
		errorMessage.SetRcode(requestMessage, dns.RcodeServerFailure)
		log.Printf("Error message: %+v", errorMessage)

		writeResponse(writer, errorMessage)
	}
}

func blockedRequest(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	responseMessage := new(dns.Msg)
	responseMessage.SetRcode(requestMessage, dns.RcodeRefused)
	log.Printf("Block response: %+v\n", responseMessage)
	writeResponse(writer, responseMessage)
}

func handler(writer dns.ResponseWriter, requestMessage *dns.Msg) {
	log.Printf("Query message: %+v\n", requestMessage)

	if isBlocked(requestMessage) {
		blockedRequest(writer, requestMessage)
	} else {
		proxyRequest(writer, requestMessage)
	}
}

func writeResponse(writer dns.ResponseWriter, message *dns.Msg) {
	if writeErr := writer.WriteMsg(message); nil == writeErr {
		log.Printf("Writer success\n")
	} else {
		log.Printf("Writer error: %s\n", writeErr)
	}
}

func main() {
	server := &dns.Server{
		Addr:    listen,
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	if serverErr := server.ListenAndServe(); nil != serverErr {
		log.Fatal(serverErr)
	}
}
