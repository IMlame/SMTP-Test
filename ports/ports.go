package ports

var TLSVersions = []uint16{
	25,   // mainly used for transmission of messages (not emails) between mail servers
	465,  // not recommended for secure connections
	587,  // TLS support
	2525, // TLS support
}
