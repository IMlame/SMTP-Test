package main

import (
	"SMTP-VALIDATOR/structs"
	"fmt"
	"net"

	"golang.org/x/net/idna"
)

func HandleSMTPScanRequest(hostname string) (structs.SMTPRecord, error) {
	hostname, err := idna.ToASCII(hostname)
	record := structs.SMTPRecord{}
	if err != nil {
		panic("Unable to convert hostname to ascii: " + err.Error())
	}
	record.Hostname = hostname
	fmt.Printf("Hostname: %s\n", hostname)
	// query for TXT record
	txtRecord, err := net.LookupTXT(hostname)
	if err != nil {
		panic("Unable to resolve txt record: " + err.Error())
	}
	record.TextRecord = txtRecord
	// query for MX records and retrieve servers with resolved IPs
	hostsIPs, err := retrieveMXRecordsWithIPs(hostname)
	if err != nil {
		panic("Failed to retrieve MX Records: " + err.Error())
	}
	for name, IPs := range hostsIPs {
		record.MXHostnames = append(record.MXHostnames, name)
		for _, IP := range IPs {
			record.ResolvedIPs = append(record.ResolvedIPs, IP.String())
		}
	}

	// TODO: check mail servers for TLS status
	// record, err = RetrieveTLSStatus(hostsIPs)
	// if err != nil {
	// 	panic("Unable to retrieve TLS status: " + err.Error())
	// }
	// retrieve TLSA
	record.MXHostnameTLSARecords = verifyIPsWithTLSARecords(hostsIPs)
	return record, nil
}
