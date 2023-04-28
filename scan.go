package main

import (
	"SMTP-VALIDATOR/network"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"

	"golang.org/x/net/idna"
)

func HandleSMTPScanRequest(Hostname string) (SMTPRecord, error) {
	hostname := "gmail.com"
	hostname, err := idna.ToASCII(hostname)
	record := SMTPRecord{}
	if err != nil {
		panic("Unable to convert hostname to ascii: " + err.Error())
	}
	fmt.Printf("Hostname: %s\n", hostname)
	// Retrieve TXT record
	txtRecord, err := net.LookupTXT(hostname)
	if err != nil {
		fmt.Printf("Failed to retrieve txt record for domain name" + err.Error() + "\n")
		// return SMTPRecord{}, errors.New("Failed to lookup text record")
	}
	record.TextRecord = txtRecord
	fmt.Printf("Text record: %s\n", &txtRecord)
	// Retrieve MX record
	mxList, err := net.LookupMX(hostname)
	if err != nil {
		fmt.Printf("Failed to retrieve mx record for domain name" + err.Error() + "\n")
		return SMTPRecord{}, errors.New("failed to lookup mail record")
	}
	// Retrieve all IPs from MXs
	hostsIPs := make(map[string][]net.IP, 0)
	for _, mx := range mxList {
		fmt.Printf("Resolving mx host: %s\n", mx.Host)
		IPs, err := network.ResolveIPAddresses(mx.Host)
		if err != nil {
			fmt.Print("Error resolving mx host: " + err.Error())
			continue
		}
		hostsIPs[mx.Host] = IPs
	}
	// Dial every IP and test for TLS (maybe piggyback off TLS-Scanner)
	for hostname, IPs := range hostsIPs {
		for _, IP := range IPs {
			fmt.Printf("Dialing hostname %s with IP: %s...\n", hostname, IP.String())
			conn, err := smtp.Dial(net.JoinHostPort(IP.String(), "25"))
			if err != nil {
				fmt.Println("\tError resolving ip: " + err.Error())
				continue
			}
			connErr := conn.StartTLS(&tls.Config{
				ServerName: hostname,
			})

			if connErr != nil {
				fmt.Printf("\tDoes not support tls :(, skipping...\n")
				continue
			}
			state, _ := conn.TLSConnectionState()
			fmt.Printf("\tSupports TLS version %d, using suite %d\n", state.Version, state.CipherSuite)
		}
	}

	// for _, mx := range mxList {
	// 	mx := "alt4.gmail-smtp-in.l.google.com."
	// 	fmt.Printf("Dialing %s...\n", mx)
	// 	conn, err := smtp.Dial(net.JoinHostPort("172.253.113.27", "25"))
	// 	if err != nil {
	// 		panic("tcp error: " + err.Error())
	// 	}
	// 	connErr := conn.StartTLS(&tls.Config{
	// 		ServerName: mx,
	// 	})
	// }

	// if connErr != nil {
	// 	fmt.Printf("\tDoes not support tls :(, skipping...\n")
	// }
	// state, _ := conn.TLSConnectionState()
	// fmt.Printf("\tSupports TLS version %d, using suite %d\n", state.Version, state.CipherSuite)

	return record, nil
}
