package main

import (
	"log"

	"github.com/miekg/dns"
)

var proxyPassAddr = "8.8.8.8:domain"

var blocked = []string {
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
	responseMessage, exchangeErr := dns.Exchange(requestMessage, proxyPassAddr)

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
		Addr:    ":1053",
		Net:     "udp",
		Handler: dns.HandlerFunc(handler),
	}

	if serverErr := server.ListenAndServe(); nil != serverErr {
		log.Fatal(serverErr)
	}
}
