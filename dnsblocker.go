package main

import (
  "log"
  "github.com/miekg/dns"
)

var proxyPassAddr = "8.8.8.8:domain"

func handler(writer dns.ResponseWriter, requestMessage *dns.Msg) {
  log.Printf("Query message: %+v\n", requestMessage)

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

func writeResponse(writer dns.ResponseWriter, message *dns.Msg) {
  if writeErr := writer.WriteMsg(message); nil == writeErr {
    log.Printf("Writer success\n")
  } else {
    log.Printf("Writer error: %s\n", writeErr)
  }
}

func main() {
  server := &dns.Server{
    Addr: ":1053",
    Net: "udp",
    Handler: dns.HandlerFunc(handler),
  }

  if serverErr := server.ListenAndServe(); nil != serverErr {
    log.Fatal(serverErr)
  }
}
