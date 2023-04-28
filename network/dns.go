package network

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

func ResolveIPAddresses(domainName string) ([]net.IP, error) {
	asciiDomainName, err := idna.ToASCII(domainName)
	IPs, err := net.LookupIP(dns.Fqdn(asciiDomainName))
	if err != nil {
		fmt.Printf("Failed to retrieve IP addresses from domain name" + err.Error() + "\n")
		return nil, errors.New("no addresses resolved for query")
	}
	return IPs, nil
}
