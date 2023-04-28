package main

import "fmt"

func main() {
	hostname := "gmail.com"
	record, error := HandleSMTPScanRequest(hostname)
	if error != nil {
		panic(error.Error())
	}
	fmt.Printf("%v\n", record)
	// Retrieve text record

}
