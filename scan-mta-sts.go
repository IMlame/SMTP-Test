package main

import (
	"SMTP-VALIDATOR/structs"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func retrieveMTASTSRecords(hostname string) structs.MTASTSRecord {
	mtaSTSRecord := structs.MTASTSRecord{}
	httpsRecord := retrieveHttpsMTASTSRecord(hostname)
	mtaSTSRecord.HTTPSRecord = httpsRecord
	textMTASTSRecord := retrieveTextMTASTSRecord(hostname)
	mtaSTSRecord.MTATextRecord = textMTASTSRecord
	return mtaSTSRecord
}

func retrieveHttpsMTASTSRecord(hostname string) structs.HTTPSRecord {
	record := structs.HTTPSRecord{}
	// Setup https connection variables. Timeout 60 seconds
	tr := &http.Transport{
		IdleConnTimeout: 60 * time.Second,
	}
	client := &http.Client{Transport: tr}
	// MTA-STS records retrieved under https://mta-sts.[hostname]/.well-known/mta-sts.txt
	requestURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", hostname)
	fmt.Printf("Retrieving MTA-STS info from %s\n", requestURL)
	res, err := client.Get(requestURL)
	if err != nil {
		record.Errors = append(record.Errors, "unable to connect to mta-sts hostname: "+err.Error())
		return record
	}
	// 	MTA-STS must be OK 200/HTTP 3XX must not be followed
	if res.StatusCode != 200 {
		record.Errors = append(record.Errors, "status code is "+string(res.StatusCode)+" and not 200")
		return record
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		record.Errors = append(record.Errors, "couldn't read mta-sts response body: "+err.Error())
		return record
	}
	// MTA-STS must be of content type "text/plain"
	contentType := http.DetectContentType(b)
	if !strings.Contains(contentType, "text/plain") {
		record.Errors = append(record.Errors, "content type was not text/plain")
		return record
	}

	record = parseByteArrIntoMTASTSRecord(b)
	return record
}

func parseByteArrIntoMTASTSRecord(bytes []byte) structs.HTTPSRecord {
	str := string(bytes)
	str = strings.ReplaceAll(str, "\r\n", "\n")
	str = strings.Trim(str, "\n")
	foundErrors := make([]string, 0)
	r := structs.HTTPSRecord{}
	for _, line := range strings.Split(str, "\n") {
		keyValue := strings.Split(line, ": ")
		if len(keyValue) != 2 {
			foundErrors = append(foundErrors, "malformed key value pair")
		}
		switch keyValue[0] {
		case "version":
			r.Version = keyValue[1]
		case "mode":
			r.Mode = keyValue[1]
		case "mx":
			r.AllowedMXPatterns = append(r.AllowedMXPatterns, keyValue[1])
		case "max_age":
			maxAge, parseIntError := strconv.Atoi(keyValue[1])
			if parseIntError != nil {
				foundErrors = append(foundErrors, "could not parse max_int value")
			} else {
				r.MaxAge = maxAge
			}
		default:
			r.Extensions = append(r.Extensions, structs.Pair{keyValue[0], keyValue[1]})
		}
	}
	// MTA-STS must contain version, mode, max_age, and at least one MX field
	if r.Version == "" {
		foundErrors = append(foundErrors, "no MTA-STS version found (required)")
	}

	if r.Mode == "" {
		foundErrors = append(foundErrors, "no MTA-STS mode found (required)")
	}

	if r.MaxAge == 0 {
		foundErrors = append(foundErrors, "no MTA-STS max age found (required)")
	}

	if len(r.AllowedMXPatterns) == 0 {
		foundErrors = append(foundErrors, "no MTA-STS allowed MX patterns found (at least one required)")
	}
	r.Errors = foundErrors
	return r
}

func retrieveTextMTASTSRecord(hostname string) structs.MTATextRecord {
	// hostname = dns.Fqdn(hostname)
	// // MTA-STS text records retrieved under "_mta-sts.[hostname]
	// hostnameDNS := fmt.Sprintf("_mta-sts.%s", hostname)
	// query := new(dns.Msg)
	// query.SetQuestion(hostnameDNS, dns.TypeTXT)

	// ans, _ := dns.Exchange(query, "1.1.1.1:53")
	// fmt.Printf("%v\n", ans.Answer)

	// for _, ansRR := range ans.Answer {
	// 	fmt.Printf("[%v] %v\n", ansRR.Header().Rrtype, ansRR)
	// }
	return structs.MTATextRecord{}
}

// for TXT, retrieve ID and version
// if CNAME exists, follow cname to get text record
