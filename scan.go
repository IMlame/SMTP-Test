package main

import (
	"SMTP-VALIDATOR/network"
	"SMTP-VALIDATOR/ports"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"

	"github.com/shuque/dane"
	"golang.org/x/net/idna"
)

func HandleSMTPScanRequest(hostname string) (SMTPRecord, error) {
	hostname, err := idna.ToASCII(hostname)
	record := SMTPRecord{}
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
		hostsIPs[mx.Host] = IPs
	}
	return hostsIPs, err
}

// Given a map of mail server hostnames and IPs, resolve TLSA status for each hostname
func verifyIPsWithTLSARecords(hostsIPs map[string][]net.IP) map[string]CombinedTLSARecord {
	allTLSARecords := make(map[string]CombinedTLSARecord, 0)
	for hostname, IPs := range hostsIPs {
		combinedTLSARecord := CombinedTLSARecord{}
		combinedTLSARecord.PortTLSARecord = make(map[int]TLSARecord)
		for _, port := range ports.SMTPPorts {
			tlsaRecord := verifySingleIPsTLSARecord(hostname, IPs, port)
			combinedTLSARecord.PortTLSARecord[port] = tlsaRecord
		}
		allTLSARecords[hostname] = combinedTLSARecord
	}
	return allTLSARecords
}

// Given mail server, queries for tlsa record, and iterates all resolved IPs for certification, returning TLSARecord.
// Errors on tlsa record lookup fail.
func verifySingleIPsTLSARecord(hostname string, IPs []net.IP, port int) TLSARecord {
	tlsaRecord := TLSARecord{}
	tlsaRecord.Port = port
	tlsaRecord.TLSARecordExists = false
	tlsaRecord.TLSAIPs = make(map[string]TLSAStatusIP)

	// Utilizing Google DNS (can change to cloudflare later, after ensuring proper behavior)
	servers := []*dane.Server{dane.NewServer("", "8.8.8.8", 53)}
	resolver := dane.NewResolver(servers)
	tlsa, err := dane.GetTLSA(resolver, hostname, port)
	if err != nil {
		tlsaRecord.TLSAError = err.Error()

		return tlsaRecord
	}
	if tlsa == nil {
		tlsaRecord.TLSAError = "no tlsa records found"
		return tlsaRecord
	}

	tlsaRecord.TLSARecordExists = true

	for _, ip := range IPs {
		daneconfig := dane.NewConfig(hostname, ip, port)
		daneconfig.TLSA = tlsa
		conn, err := smtp.Dial(net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			tlsaRecord.TLSAIPs[ip.String()] = TLSAStatusIP{false, "TCP error: " + err.Error()}
			continue
		}
		connErr := conn.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		})
		if connErr != nil {
			tlsaRecord.TLSAIPs[ip.String()] = TLSAStatusIP{false, "TLS connection error: " + connErr.Error()}
		}
		state, ok := conn.TLSConnectionState()
		if !ok {
			tlsaRecord.TLSAIPs[ip.String()] = TLSAStatusIP{false, "TLSConnectionState error"}
		}
		daneconfig.DANEChains = append(daneconfig.DANEChains, state.PeerCertificates)
		dane.AuthenticateAll(daneconfig)
		conn.Close()
		// NOTE: can check validity of certificate chain with daneconfig.Okpkix
		if daneconfig.Okdane {
			tlsaRecord.TLSAIPs[ip.String()] = TLSAStatusIP{true, ""}
			fmt.Printf("Result: DANE OK\n")
		} else {
			tlsaRecord.TLSAIPs[ip.String()] = TLSAStatusIP{false, "failed to find matching TLSA record"}
		}
	}
	return tlsaRecord
}

// Temporary: (PIGGY BACK OFF TLS-Scanner)
func RetrieveTLSStatus(hostsIPs map[string][]net.IP) (SMTPRecord, error) {
	// Dial every IP and test for TLS.
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
	return SMTPRecord{}, nil
}
