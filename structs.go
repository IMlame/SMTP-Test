package main

type SMTPRecord struct {
	Hostname    string
	TextRecord  []string
	MXHostnames []string
	ResolvedIPs []string
}
