package panel

import (
	"net/http"

	"github.com/ixabolfazl/tls-relay/internal/updatecheck"
)

func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	curVer := s.version
	checker := s.updateChecker
	s.mu.RUnlock()

	enabled := true
	if s.sqlStore != nil {
		if val, found, err := s.sqlStore.GetSetting(r.Context(), "update_check_enabled"); err == nil && found {
			enabled = (val != "false")
		}
	}

	if !enabled {
		jsonOK(w, map[string]interface{}{
			"enabled":         false,
			"current_version": curVer,
		})
		return
	}

	if checker == nil {
		checker = updatecheck.NewChecker(curVer)
	}

	info, err := checker.Latest(r.Context())
	if err != nil && info.LatestVersion == "" {
		jsonOK(w, map[string]interface{}{
			"enabled":          true,
			"current_version":  curVer,
			"update_available": false,
			"error":            err.Error(),
		})
		return
	}

	jsonOK(w, map[string]interface{}{
		"enabled":           true,
		"current_version":   info.CurrentVersion,
		"latest_version":    info.LatestVersion,
		"update_available":  info.UpdateAvailable,
		"release_url":       info.ReleaseURL,
		"release_notes_url": info.ReleaseNotesURL,
		"checked_at":        info.CheckedAt,
	})
}
