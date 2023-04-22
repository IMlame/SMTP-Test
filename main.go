package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
)

func main() {
	hostname := "gmail.com"
	fmt.Printf("Hostname: %s\n", hostname)

	txtRecord, err := net.LookupTXT(hostname)
	if err != nil {
		panic("MX lookup failed: " + err.Error())
	}
	fmt.Printf("Text record: %s\n", &txtRecord)

	mxList, err := net.LookupMX(hostname)
	if err != nil {
		panic("MX lookup failed: " + err.Error())
	}
	// Test TLS (and other things?)
	for _, mx := range mxList {
		fmt.Printf("Dialing %s...\n", mx.Host)
		conn, err := smtp.Dial(net.JoinHostPort(mx.Host, "smtp"))
		if err != nil {
			panic("tcp error: " + err.Error())
		}
		connErr := conn.StartTLS(&tls.Config{
			ServerName: mx.Host,
		})

		if connErr != nil {
			fmt.Printf("\tDoes not support tls :(, skipping...\n")
			continue
		}
		state, _ := conn.TLSConnectionState()
		fmt.Printf("\tSupports TLS version %d, using suite %d\n", state.Version, state.CipherSuite)
	}

	// Retrieve text record

}
