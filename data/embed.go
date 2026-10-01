package data

import _ "embed"

// DefaultDomainsJSON contains the embedded default domains catalog JSON.
//
//go:embed default-domains.json
var DefaultDomainsJSON []byte
