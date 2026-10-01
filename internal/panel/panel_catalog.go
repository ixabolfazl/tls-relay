package panel

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ixabolfazl/tls-relay/internal/catalog"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

type catalogTreeSubcategory struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Enabled            bool   `json:"enabled"`
	DomainCount        int    `json:"domain_count"`
	EnabledDomainCount int    `json:"enabled_domain_count"`
}

type catalogTreeCategory struct {
	ID                 string                   `json:"id"`
	Name               string                   `json:"name"`
	Enabled            bool                     `json:"enabled"`
	DomainCount        int                      `json:"domain_count"`
	EnabledDomainCount int                      `json:"enabled_domain_count"`
	Subcategories      []catalogTreeSubcategory `json:"subcategories"`
}

type catalogTreeResponse struct {
	InstalledVersion int                   `json:"installed_version"`
	Categories       []catalogTreeCategory `json:"categories"`
}

type catalogStatusResponse struct {
	InstalledVersion int    `json:"installed_version"`
	EmbeddedVersion  int    `json:"embedded_version"`
	RemoteVersion    int    `json:"remote_version"`
	RemoteError      string `json:"remote_error"`
	UpdateAvailable  bool   `json:"update_available"`
}

type catalogPreviewRequest struct {
	Source string `json:"source"` // "embedded" | "github"
}

type catalogLoadRequest struct {
	Source          string `json:"source"` // "embedded" | "github"
	ExpectedVersion int    `json:"expected_version"`
}

type updateCatalogNodeRequest struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Name    string `json:"name,omitempty"`
}

type createCatalogNodeRequest struct {
	ID       string `json:"id,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
}

func parseNodeIDParam(r *http.Request) string {
	raw := r.PathValue("id")
	decoded, err := url.PathUnescape(raw)
	if err == nil && decoded != "" {
		return decoded
	}
	return raw
}

func (s *Server) getInstalledCatalogVersion(r *http.Request) int {
	if s.sqlStore == nil {
		return 0
	}
	val, ok, err := s.sqlStore.GetSetting(r.Context(), sqlitestore.SettingCatalogVersion)
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(val))
	return n
}

func (s *Server) resolveCatalogSource(r *http.Request, source string) (*catalog.Catalog, error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "embedded":
		return catalog.Embedded()
	case "github":
		if s.catalogChecker == nil {
			return nil, fmt.Errorf("catalog checker not configured")
		}
		return s.catalogChecker.Latest(r.Context())
	default:
		return nil, fmt.Errorf("invalid source %q (must be 'embedded' or 'github')", source)
	}
}

// handleGetCatalog returns the catalog tree of categories and subcategories.
func (s *Server) handleGetCatalog(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonOK(w, catalogTreeResponse{InstalledVersion: 0, Categories: []catalogTreeCategory{}})
		return
	}

	nodes, err := s.sqlStore.ListCatalogNodes(r.Context())
	if err != nil {
		slog.Error("listing catalog nodes error", "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	installedVersion := s.getInstalledCatalogVersion(r)

	// Map categories and subcategories
	var categories []catalogTreeCategory
	catIndex := make(map[string]int)

	for _, n := range nodes {
		if n.ParentID == "" {
			catIndex[n.ID] = len(categories)
			categories = append(categories, catalogTreeCategory{
				ID:                 n.ID,
				Name:               n.Name,
				Enabled:            n.Enabled,
				DomainCount:        n.DomainCount,
				EnabledDomainCount: n.EnabledDomainCount,
				Subcategories:      []catalogTreeSubcategory{},
			})
		}
	}

	for _, n := range nodes {
		if n.ParentID != "" {
			if idx, ok := catIndex[n.ParentID]; ok {
				categories[idx].Subcategories = append(categories[idx].Subcategories, catalogTreeSubcategory{
					ID:                 n.ID,
					Name:               n.Name,
					Enabled:            n.Enabled,
					DomainCount:        n.DomainCount,
					EnabledDomainCount: n.EnabledDomainCount,
				})
			}
		}
	}

	if categories == nil {
		categories = []catalogTreeCategory{}
	}

	jsonOK(w, catalogTreeResponse{
		InstalledVersion: installedVersion,
		Categories:       categories,
	})
}

// handleGetCatalogStatus returns the status of installed, embedded, and remote catalogs.
func (s *Server) handleGetCatalogStatus(w http.ResponseWriter, r *http.Request) {
	installedVersion := s.getInstalledCatalogVersion(r)

	embeddedVersion := 0
	emb, err := catalog.Embedded()
	if err == nil && emb != nil {
		embeddedVersion = emb.Version
	}

	remoteVersion := 0
	remoteErrStr := ""
	refresh := r.URL.Query().Get("refresh") == "1"

	if s.catalogChecker != nil {
		var rem *catalog.Catalog
		var remErr error
		if refresh {
			rem, remErr = s.catalogChecker.ForceRefresh(r.Context())
		} else {
			rem, remErr = s.catalogChecker.Latest(r.Context())
		}
		if remErr != nil {
			remoteErrStr = remErr.Error()
		} else if rem != nil {
			remoteVersion = rem.Version
		}
	}

	maxCandidate := embeddedVersion
	if remoteErrStr == "" && remoteVersion > maxCandidate {
		maxCandidate = remoteVersion
	}
	updateAvailable := maxCandidate > installedVersion

	jsonOK(w, catalogStatusResponse{
		InstalledVersion: installedVersion,
		EmbeddedVersion:  embeddedVersion,
		RemoteVersion:    remoteVersion,
		RemoteError:      remoteErrStr,
		UpdateAvailable:  updateAvailable,
	})
}

// handlePreviewCatalog runs a dry-run apply of the catalog from the selected source.
func (s *Server) handlePreviewCatalog(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "store not configured", http.StatusInternalServerError)
		return
	}

	var req catalogPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	cat, err := s.resolveCatalogSource(r, req.Source)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.sqlStore.ApplyCatalog(r.Context(), cat, true)
	if err != nil {
		slog.Error("preview catalog apply error", "error", err)
		jsonErr(w, "preview error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, result)
}

// handleLoadCatalog applies the catalog from the selected source after validating expected version.
func (s *Server) handleLoadCatalog(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "store not configured", http.StatusInternalServerError)
		return
	}

	var req catalogLoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	cat, err := s.resolveCatalogSource(r, req.Source)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ExpectedVersion <= 0 {
		jsonErr(w, "expected_version is required", http.StatusBadRequest)
		return
	}

	if cat.Version != req.ExpectedVersion {
		jsonErr(w, fmt.Sprintf("catalog version mismatch: previewed %d, current source version is %d",
			req.ExpectedVersion, cat.Version), http.StatusConflict)
		return
	}

	result, err := s.sqlStore.ApplyCatalog(r.Context(), cat, false)
	if err != nil {
		slog.Error("apply catalog error", "error", err)
		jsonErr(w, "apply error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = s.refreshDomains(r.Context())

	slog.Info("catalog applied successfully",
		"version", cat.Version,
		"source", req.Source,
		"domains_added", result.DomainsAdded,
		"domains_updated", result.DomainsUpdated,
		"remote_addr", r.RemoteAddr,
	)

	jsonOK(w, result)
}

// handleUpdateCatalogNode updates a catalog category or subcategory node (toggle enabled or edit name).
func (s *Server) handleUpdateCatalogNode(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "store not configured", http.StatusInternalServerError)
		return
	}

	id := parseNodeIDParam(r)
	if id == "" {
		jsonErr(w, "node id is required", http.StatusBadRequest)
		return
	}

	var req updateCatalogNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	affected := 0
	if req.Enabled != nil {
		var err error
		affected, err = s.sqlStore.SetCatalogNodeEnabled(r.Context(), id, *req.Enabled)
		if err != nil {
			slog.Error("set catalog node enabled error", "id", id, "error", err)
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = s.refreshDomains(r.Context())
	}

	if req.Name != "" {
		if err := s.sqlStore.UpdateCatalogNode(r.Context(), id, req.Name); err != nil {
			slog.Error("update catalog node error", "id", id, "error", err)
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	jsonOK(w, map[string]interface{}{
		"success":          true,
		"affected_domains": affected,
	})
}

// handleCreateCatalogNode creates a new custom category or subcategory node.
func (s *Server) handleCreateCatalogNode(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "store not configured", http.StatusInternalServerError)
		return
	}

	var req createCatalogNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.Name = catalog.SanitizeName(req.Name)
	if req.Name == "" {
		jsonErr(w, "name is required", http.StatusBadRequest)
		return
	}

	nodeID := strings.ToLower(strings.TrimSpace(req.ID))
	parentID := strings.ToLower(strings.TrimSpace(req.ParentID))

	if nodeID == "" {
		// Generate slug from name
		slug := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			if r == ' ' {
				return '-'
			}
			return -1
		}, strings.ToLower(req.Name))
		slug = strings.Trim(slug, "-_")
		if slug == "" {
			slug = "item"
		}
		if parentID != "" {
			nodeID = parentID + "." + slug
		} else {
			nodeID = slug
		}
	}

	if err := s.sqlStore.CreateCatalogNode(r.Context(), nodeID, parentID, req.Name); err != nil {
		slog.Error("create catalog node error", "error", err)
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]interface{}{
		"id":        nodeID,
		"parent_id": parentID,
		"name":      req.Name,
	})
}

// handleDeleteCatalogNode deletes a custom category or subcategory node.
func (s *Server) handleDeleteCatalogNode(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "store not configured", http.StatusInternalServerError)
		return
	}

	id := parseNodeIDParam(r)
	if id == "" {
		jsonErr(w, "node id is required", http.StatusBadRequest)
		return
	}

	if err := s.sqlStore.DeleteCatalogNode(r.Context(), id); err != nil {
		slog.Error("delete catalog node error", "id", id, "error", err)
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	_ = s.refreshDomains(r.Context())
	jsonOK(w, map[string]interface{}{"success": true})
}
