package main

import (
	"SMTP-VALIDATOR/network"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Given mail server hostname, return corresponding mail servers mapped to resolved IPs
func retrieveMXRecordsWithIPs(hostname string) (map[string][]net.IP, error) {
	// Retrieve MX records
	hostsIPs := make(map[string][]net.IP, 0) // hostname : IPs
	mxList, err := net.LookupMX(hostname)
	if err != nil {
		fmt.Printf("Failed to retrieve mx record for domain name" + err.Error() + "\n")
		return hostsIPs, errors.New("failed to lookup mail record")
	}
	// Retrieve all IPs from MXs
	for _, mx := range mxList {
		fmt.Printf("Resolving mx host: %s\n", mx.Host)
		IPs, err := network.ResolveIPAddresses(mx.Host)
		if err != nil {
			//fmt.Print("Error resolving mx host: " + err.Error())
			continue
		}
		hostsIPs[strings.TrimRight(mx.Host, ".")] = IPs
	}
	return hostsIPs, err
}
