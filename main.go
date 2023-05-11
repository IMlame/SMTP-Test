package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	hostname := "gmail.com"
	r := retrieveMTASTSRecords(hostname)
	jsonData, _ := json.Marshal(r)
	fmt.Println(string(jsonData))

	record, error := HandleSMTPScanRequest(hostname)
	if error != nil {
		panic("Error handling SMTP scan: " + error.Error())
	}
	jsonData, err := json.Marshal(record)
	if err != nil {
		panic("Error marshaling record: " + err.Error())
	}
	fmt.Println(string(jsonData))
}
