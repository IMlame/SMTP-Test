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
	HTTPSRecord    HTTPSRecord                  `json:"httpsRecord"`
	MTATextRecord  MTATextRecord                `json:"txtRecord"`
	ValidHostnames []MTASTSMailHostnameValidity `json:"mxValidity"`
}

type HTTPSRecord struct {
	Version           string   `json:"version"`
	Mode              string   `json:"mode"`
	MaxAge            int      `json:"maxAge"`
	AllowedMXPatterns []string `json:"allowedMXPatterns"`
	Errors            []string `json:"httpsErrors"`
	Extensions        []Pair   `json:"extensions"`
	Valid             bool     `json:"valid"`
}

type MTATextRecord struct {
	Version string   `json:"version"`
	ID      string   `json:"id"`
	Other   []Pair   `json:"other"`
	Errors  []string `json:"errors"`
	Valid   bool     `json:"valid"`
}

type MTASTSMailHostnameValidity struct {
	Hostname string `json:"mx"`
	Valid    bool   `json:"valid"`
}

type Pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
