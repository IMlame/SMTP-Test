package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	hostname := "eugeni.torproject.org."
	// port := 25
	record, error := HandleSMTPScanRequest(hostname)
	if error != nil {
		panic("Error handling SMTP scan: " + error.Error())
	}
	jsonData, err := json.Marshal(record)
	if err != nil {
		panic("Error marshaling record: " + err.Error())
	}
	fmt.Println(string(jsonData))
	// // port := 25
	// servers := []*dane.Server{dane.NewServer("", "8.8.8.8", 53)}
	// resolver := dane.NewResolver(servers)
	// tlsa, _ := dane.GetTLSA(resolver, hostname, port)

	// iplist, _ := dane.GetAddresses(resolver, hostname, true)

	// for _, ip := range iplist {
	// 	daneconfig := dane.NewConfig(hostname, ip, port)
	// 	daneconfig.TLSA = tlsa
	// 	conn, err := smtp.Dial(net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	// 	if err != nil {
	// 		continue
	// 		// panic("connection error: " + err.Error())
	// 	}
	// 	connErr := conn.StartTLS(&tls.Config{
	// 		InsecureSkipVerify: true,
	// 		ServerName:         hostname,
	// 	})
	// 	if connErr != nil {
	// 		fmt.Printf("\tDoes not support tls :(, skipping... " + connErr.Error() + "\n")
	// 	}
	// 	state, ok := conn.TLSConnectionState()
	// 	if !ok {
	// 		panic("state error" + err.Error())
	// 	}
	// 	fmt.Printf("%v", state)
	// 	daneconfig.DANEChains = append(daneconfig.DANEChains, state.PeerCertificates)
	// 	dane.AuthenticateAll(daneconfig)
	// 	// daneconfig := dane.NewConfig(hostname, ip, port)
	// 	// daneconfig.Appname = "smtp"
	// 	// daneconfig.SetTLSA(tlsa)
	// 	// conn, err := dane.DialTLS(daneconfig)
	// 	if err != nil {
	// 		fmt.Printf("Result: FAILED: %s\n", err.Error())
	// 		continue
	// 	}
	// 	if daneconfig.Okdane {
	// 		fmt.Printf("Result: DANE OK\n")
	// 	} else if daneconfig.Okpkix {
	// 		fmt.Printf("Result: PKIX OK\n")
	// 	} else {
	// 		fmt.Printf("Result: FAILED\n")
	// 	}
	// 	//
	// 	// do some stuff with the obtained TLS connection here
	// 	//
	// 	conn.Close()
	// }
}
