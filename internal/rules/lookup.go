package rules

// IsConfigured returns true if the hostname matches any rule in the store
// (regardless of port). Used by the DNS resolver to decide whether to
// redirect a query to the relay IP.
func (rs *RuleStore) IsConfigured(hostname string) bool {
	snap := rs.snapshot.Load()

	if _, ok := snap.exact[hostname]; ok {
		return true
	}
	for _, wc := range snap.wildcards {
		if matchesWildcard(hostname, wc.suffix) {
			return true
		}
	}
	return false
}
