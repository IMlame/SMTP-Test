package main

import (
	"SMTP-VALIDATOR/ports"
	"SMTP-VALIDATOR/structs"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"

	"github.com/shuque/dane"
)

// Given a map of mail server hostnames and IPs, resolve TLSA status for each hostname
func verifyIPsWithTLSARecords(hostsIPs map[string][]net.IP) map[string]structs.CombinedTLSARecord {
	allTLSARecords := make(map[string]structs.CombinedTLSARecord, 0)
	for hostname, IPs := range hostsIPs {
		combinedTLSARecord := structs.CombinedTLSARecord{}
		combinedTLSARecord.PortTLSARecord = make(map[int]structs.TLSARecord)
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
func verifySingleIPsTLSARecord(hostname string, IPs []net.IP, port int) structs.TLSARecord {
	tlsaRecord := structs.TLSARecord{}
	tlsaRecord.Port = port
	tlsaRecord.TLSARecordExists = false
	tlsaRecord.TLSAIPs = make(map[string]structs.TLSAStatusIP)

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
			tlsaRecord.TLSAIPs[ip.String()] = structs.TLSAStatusIP{false, "TCP error: " + err.Error()}
			continue
		}
		connErr := conn.StartTLS(&tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		})
		if connErr != nil {
			tlsaRecord.TLSAIPs[ip.String()] = structs.TLSAStatusIP{false, "TLS connection error: " + connErr.Error()}
		}
		state, ok := conn.TLSConnectionState()
		if !ok {
			tlsaRecord.TLSAIPs[ip.String()] = structs.TLSAStatusIP{false, "TLSConnectionState error"}
		}
		daneconfig.DANEChains = append(daneconfig.DANEChains, state.PeerCertificates)
		dane.AuthenticateAll(daneconfig)
		conn.Close()
		// NOTE: can check validity of certificate chain with daneconfig.Okpkix
		if daneconfig.Okdane {
			tlsaRecord.TLSAIPs[ip.String()] = structs.TLSAStatusIP{true, ""}
			fmt.Printf("Result: DANE OK\n")
		} else {
			tlsaRecord.TLSAIPs[ip.String()] = structs.TLSAStatusIP{false, "failed to find matching TLSA record"}
		}
	}
	return tlsaRecord
}

// Temporary: (PIGGY BACK OFF TLS-Scanner)
func RetrieveTLSStatus(hostsIPs map[string][]net.IP) (structs.SMTPRecord, error) {
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
	return structs.SMTPRecord{}, nil
}
