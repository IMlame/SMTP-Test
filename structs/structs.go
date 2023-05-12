package structs

type SMTPRecord struct {
	Hostname              string                        `json:"hostname"`
	TextRecord            []string                      `json:"textRecord"`
	MXHostnames           []string                      `json:"mxHostnames"`
	ResolvedIPs           []string                      `json:"resolvedIPs"`
	MXHostnameTLSARecords map[string]CombinedTLSARecord `json:"mxHostnameTLSARecords"`
	MTASTSRecord          MTASTSRecord                  `json:"mtastsRecord"`
}

// Datastructure to hold all TLSARecords associated with a hostname
type CombinedTLSARecord struct {
	PortTLSARecord map[int]TLSARecord `json:"portTLSARecord"`
}

// Holds TLSA record results, based on port and hostname
type TLSARecord struct {
	TLSARecordExists bool                    `json:"tlsaRecordExists"`
	Port             int                     `json:"port"`
	TLSAError        string                  `json:"tlsaError"`
	TLSAIPs          map[string]TLSAStatusIP `json:"tlsaIPs"` // IP : TLSAStatusIP
}

type TLSAStatusIP struct {
	Verified bool   `json:"verified"` // matches a TLSA record
	Error    string `json:"error"`
}

type MTASTSRecord struct {
	HTTPSRecord    HTTPSRecord                  `json:"httpsMTASTSRecord"`
	MTATextRecord  MTATextRecord                `json:"txtMTASTSRecord"`
	ValidHostnames []MTASTSMailHostnameValidity `json:"validMTASTSMXs"`
}

type HTTPSRecord struct {
	Version           string   `json:"mtaHTTPSVersion"`
	Mode              string   `json:"mode"`
	MaxAge            int      `json:"maxAge"`
	AllowedMXPatterns []string `json:"allowedMXPatterns"`
	Errors            []string `json:"httpsErrors"`
	Extensions        []Pair   `json:"extensions"`
	Valid             bool     `json:"mtaHTTPSValid"`
}

type MTATextRecord struct {
	Version string   `json:"mtaTextVersion"`
	ID      string   `json:"mtaTextID"`
	Other   []Pair   `json:"mtaTextOther"`
	Errors  []string `json:"mtaTextErrors"`
	Valid   bool     `json:"mtaTextValid"`
}

type MTASTSMailHostnameValidity struct {
	Hostname string `json:"mtaVerifiedHostname"`
	Valid    bool   `json:"mtaValidHostname"`
}

type Pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
