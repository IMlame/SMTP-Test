package main

import (
	"SMTP-VALIDATOR/structs"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func retrieveMTASTSRecords(hostname string, mailServers []string) structs.MTASTSRecord {
	mtaSTSRecord := structs.MTASTSRecord{}
	mtaSTSRecord.HTTPSRecord = retrieveHttpsMTASTSRecord(hostname)
	mtaSTSRecord.MTATextRecord = retrieveTextMTASTSRecord(hostname)
	mtaSTSRecord.ValidHostnames = validateMailServersWithHTTPSRecords(mtaSTSRecord.HTTPSRecord.AllowedMXPatterns, mailServers)
	return mtaSTSRecord
}

func retrieveHttpsMTASTSRecord(hostname string) structs.HTTPSRecord {
	record := structs.HTTPSRecord{}
	record.Valid = false
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
		record.Errors = append(record.Errors, "status code is "+fmt.Sprint(res.StatusCode)+" and not 200")
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
	if len(record.Errors) == 0 {
		record.Valid = true
	}
	return record
}

func parseByteArrIntoMTASTSRecord(bytes []byte) structs.HTTPSRecord {
	str := string(bytes)
	str = strings.ReplaceAll(str, "\r\n", "\n")
	str = strings.Trim(str, "\n")
	r := structs.HTTPSRecord{}
	for _, line := range strings.Split(str, "\n") {
		keyValue := strings.Split(line, ": ")
		if len(keyValue) != 2 {
			r.Errors = append(r.Errors, "malformed key value pair")
			continue
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
				r.Errors = append(r.Errors, "could not parse max_int value")
			} else {
				r.MaxAge = maxAge
			}
		default:
			r.Extensions = append(r.Extensions, structs.Pair{Key: keyValue[0], Value: keyValue[1]})
		}
	}
	// MTA-STS must contain version, mode, max_age, and at least one MX field
	if r.Version == "" {
		r.Errors = append(r.Errors, "no MTA-STS version found (required)")
	}

	if r.Mode == "" {
		r.Errors = append(r.Errors, "no MTA-STS mode found (required)")
	}

	if r.MaxAge == 0 {
		r.Errors = append(r.Errors, "no MTA-STS max age found (required)")
	}

	if len(r.AllowedMXPatterns) == 0 {
		r.Errors = append(r.Errors, "no MTA-STS allowed MX patterns found (at least one required)")
	}
	return r
}

func retrieveTextMTASTSRecord(hostname string) structs.MTATextRecord {
	record := structs.MTATextRecord{}
	record.Valid = true

	hostname = dns.Fqdn(hostname)
	// MTA-STS text records retrieved under "_mta-sts.[hostname]
	hostnameDNS := fmt.Sprintf("_mta-sts.%s", hostname)
	query := new(dns.Msg)

	query.SetQuestion(hostnameDNS, dns.TypeTXT)

	ans, _ := dns.Exchange(query, "1.1.1.1:53")

	for _, ansRR := range ans.Answer {
		if t, ok := ansRR.(*dns.TXT); ok {
			version := ""
			id := ""
			other := make([]structs.Pair, 0)
			// convert "v=STSv1; id=20190429T010101;"" to "v=STSv1 id=20190429T010101"
			txtStr := strings.ReplaceAll(t.Txt[0], ";", "")
			// convert to [v=STSv1, id=20190429T010101]
			attributes := strings.Split(txtStr, " ")
			for index, token := range attributes {
				keyValue := strings.Split(token, "=")
				if len(keyValue) != 2 {
					record.Errors = append(record.Errors, "invalid key value syntax")
					break
				}
				// first key value pair MUST be version
				if index == 0 && keyValue[0] != "v" {
					record.Errors = append(record.Errors, "first attribute is not version!")
					break
				}

				switch keyValue[0] {
				case "v":
					version = keyValue[1]
				case "id":
					id = keyValue[1]
				default:
					other = append(other, structs.Pair{Key: keyValue[0], Value: keyValue[1]})
				}
			}
			// possible invalid sequences
			if version == "" {
				record.Errors = append(record.Errors, "missing required version")
				continue
			} else if id == "" {
				record.Errors = append(record.Errors, "missing required id")
				continue
			} else if version != "" && id != "" && record.Version != "" {
				// if more than one valid MTA-STS record exists, then error
				record.Errors = append(record.Errors, "more than one valid MTA-STS TXT record, not allowed!")
				record.Valid = false
				continue
			}
			// valid, woo! store the version, id, and other fields
			record.Version = version
			record.ID = id
			record.Other = other

		}
	}
	// mta not valid if no record is found
	if record.Version == "" || record.ID == "" {
		record.Valid = false
	}
	return record
}

func validateMailServersWithHTTPSRecords(allowedMXPatterns []string, mailServers []string) []structs.MTASTSMailHostnameValidity {
	validMXs := make(map[string]string, 0)

	for _, pattern := range allowedMXPatterns {
		isRegex := strings.HasPrefix(pattern, "*")
		pattern = strings.TrimLeft(pattern, "*")
		for _, mx := range mailServers {
			if (isRegex && strings.Index(mx, pattern)+len(pattern) == len(mx)) || mx == pattern {
				validMXs[mx] = pattern
			}
		}
	}

	mxValidityList := make([]structs.MTASTSMailHostnameValidity, 0)
	for _, mx := range mailServers {
		if _, ok := validMXs[mx]; ok {
			mxValidityList = append(mxValidityList, structs.MTASTSMailHostnameValidity{Hostname: mx, Valid: true})
		} else {
			mxValidityList = append(mxValidityList, structs.MTASTSMailHostnameValidity{Hostname: mx, Valid: false})
		}
	}
	return mxValidityList
}

// for TXT, retrieve ID and version
// if CNAME exists, follow cname to get text record
