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
	// QUERY FOR TXT
	txtRecord, err := net.LookupTXT(hostname)
	if err != nil {
		panic("Unable to resolve txt record: " + err.Error())
	}
	record.TextRecord = txtRecord
	// QUERY FOR MX + IPS
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
	// QUERY FOR TLSA
	record.MXHostnameTLSARecords = verifyIPsWithTLSARecords(hostsIPs)
	// QUERY FOR MTASTS
	record.MTASTSRecord = retrieveMTASTSRecords(hostname, record.MXHostnames)
	return record, nil
}
