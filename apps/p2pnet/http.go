// SPDX-License-Identifier: Apache-2.0 OR MIT

package p2pnet

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// Server exposes a Node's P2P discovery, DHT, routing, and sovereignty control
// surface over both github.com/zap-proto/zip and standard-library net/http.
type Server struct {
	Node *Node
	Now  func() int64
}

// NewServer wraps node in a dual-surface HTTP control server.
func NewServer(node *Node) (*Server, error) {
	if node == nil {
		return nil, errors.New("p2pnet: nil node")
	}
	return &Server{
		Node: node,
		Now:  func() int64 { return time.Now().Unix() },
	}, nil
}

func (s *Server) nowUnix() int64 {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().Unix()
}

type healthResponse struct {
	Service               string          `json:"service"`
	Status                string          `json:"status"`
	ProtocolVersion       string          `json:"protocolVersion"`
	PeerID                PeerID          `json:"peerId"`
	NATMode               NATReachability `json:"natMode"`
	Role                  NodeRole        `json:"role"`
	RoutingTableSize      int             `json:"routingTableSize"`
	VerifiedAnnouncements int             `json:"verifiedAnnouncements"`
	HanzoCalls            int64           `json:"hanzoCalls"`
	HanzoRegistryDisabled bool            `json:"hanzoRegistryDisabled"`
}

func (s *Server) buildHealth() healthResponse {
	now := s.nowUnix()
	return healthResponse{
		Service:               "p2pnet",
		Status:                "ok",
		ProtocolVersion:       ProtocolVersion,
		PeerID:                s.Node.ID.PeerID,
		NATMode:               s.Node.Config.NATMode,
		Role:                  s.Node.Config.Role,
		RoutingTableSize:      s.Node.Table.Size(),
		VerifiedAnnouncements: len(s.Node.Store.ListAnnouncements(now)),
		HanzoCalls:            s.Node.HanzoCalls(),
		HanzoRegistryDisabled: s.Node.Config.HanzoRegistryDisabled,
	}
}

func statusForError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrPeerIDMismatch), errors.Is(err, ErrInvalidPublicKey), errors.Is(err, ErrBundleTampered):
		return http.StatusForbidden
	case errors.Is(err, ErrSequenceRollback), errors.Is(err, ErrReplayNonce):
		return http.StatusConflict
	case errors.Is(err, ErrSybilFloodDetected):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrNoRouteFound), errors.Is(err, ErrRelayUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// Mount attaches the HIP-1350 P2P discovery & routing REST API onto a *zip.App
// under /v1/p2p with zero host dependencies.
func Mount(app *zip.App, _ luxlog.Logger, srv *Server) error {
	if app == nil {
		return errors.New("p2pnet: nil app")
	}
	if srv == nil || srv.Node == nil {
		return errors.New("p2pnet: nil server or node")
	}

	g := app.Group("/v1/p2p")
	g.Raw(http.MethodGet, "/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, srv.buildHealth())
	})
	g.Raw(http.MethodGet, "/peers", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, map[string]any{
			"peerId": srv.Node.ID.PeerID,
			"peers":  srv.Node.Table.AllPeers(),
		})
	})
	g.Raw(http.MethodGet, "/announcements", func(c *zip.Ctx) error {
		model := strings.TrimSpace(c.Query("model"))
		now := srv.nowUnix()
		var data []CapabilityAnnouncement
		if model != "" {
			data = srv.Node.Store.ProvidersForModel(model, now)
		} else {
			data = srv.Node.Store.ListAnnouncements(now)
		}
		return c.JSON(http.StatusOK, map[string]any{"data": data})
	})
	g.Raw(http.MethodPost, "/announcements", func(c *zip.Ctx) error {
		var ann CapabilityAnnouncement
		if err := json.Unmarshal(c.Body(), &ann); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		sender := PeerID(strings.TrimSpace(c.Header("X-P2P-Sender")))
		if err := srv.Node.SubmitAnnouncement(c.Context(), ann, sender); err != nil {
			return c.JSON(statusForError(err), map[string]string{"error": err.Error(), "reason": RejectReason(err)})
		}
		return c.JSON(http.StatusCreated, ann)
	})
	g.Raw(http.MethodGet, "/providers", func(c *zip.Ctx) error {
		model := strings.TrimSpace(c.Query("model"))
		if model == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "model query parameter required"})
		}
		provs := srv.Node.FindProviders(c.Context(), model)
		return c.JSON(http.StatusOK, map[string]any{"model": model, "providers": provs})
	})
	g.Raw(http.MethodPost, "/route", func(c *zip.Ctx) error {
		var req InferenceRequest
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		res, err := srv.Node.RouteInference(c.Context(), req)
		if err != nil {
			return c.JSON(statusForError(err), map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, res)
	})
	g.Raw(http.MethodGet, "/export", func(c *zip.Ctx) error {
		bundle, err := srv.Node.ExportMeshBundle(srv.nowUnix())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, bundle)
	})
	g.Raw(http.MethodPost, "/verify-bundle", func(c *zip.Ctx) error {
		var bundle MeshExportBundle
		if err := json.Unmarshal(c.Body(), &bundle); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if err := VerifyMeshBundle(bundle, srv.nowUnix(), srv.Node.Config.Policy); err != nil {
			return c.JSON(statusForError(err), map[string]any{"verified": false, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]any{
			"verified":          true,
			"exporterPeerId":    bundle.ExporterPeerID,
			"stateDigest":       bundle.StateDigest,
			"announcementCount": len(bundle.Announcements),
			"verificationClass": bundle.VerificationClass,
		})
	})
	g.Raw(http.MethodGet, "/telemetry", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, srv.Node.Telemetry())
	})
	return nil
}

// Handler returns a standalone standard-library net/http handler serving the
// exact same /v1/p2p/* control surface for operators running without zip.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/p2p/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.buildHealth())
	})
	mux.HandleFunc("/v1/p2p/peers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"peerId": s.Node.ID.PeerID,
			"peers":  s.Node.Table.AllPeers(),
		})
	})
	mux.HandleFunc("/v1/p2p/announcements", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			model := strings.TrimSpace(r.URL.Query().Get("model"))
			now := s.nowUnix()
			var data []CapabilityAnnouncement
			if model != "" {
				data = s.Node.Store.ProvidersForModel(model, now)
			} else {
				data = s.Node.Store.ListAnnouncements(now)
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": data})
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			var ann CapabilityAnnouncement
			if err := json.Unmarshal(body, &ann); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			sender := PeerID(strings.TrimSpace(r.Header.Get("X-P2P-Sender")))
			if err := s.Node.SubmitAnnouncement(r.Context(), ann, sender); err != nil {
				writeJSON(w, statusForError(err), map[string]string{"error": err.Error(), "reason": RejectReason(err)})
				return
			}
			writeJSON(w, http.StatusCreated, ann)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})
	mux.HandleFunc("/v1/p2p/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		model := strings.TrimSpace(r.URL.Query().Get("model"))
		if model == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model query parameter required"})
			return
		}
		provs := s.Node.FindProviders(r.Context(), model)
		writeJSON(w, http.StatusOK, map[string]any{"model": model, "providers": provs})
	})
	mux.HandleFunc("/v1/p2p/route", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var req InferenceRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := s.Node.RouteInference(r.Context(), req)
		if err != nil {
			writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("/v1/p2p/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		bundle, err := s.Node.ExportMeshBundle(s.nowUnix())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	})
	mux.HandleFunc("/v1/p2p/verify-bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var bundle MeshExportBundle
		if err := json.Unmarshal(body, &bundle); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := VerifyMeshBundle(bundle, s.nowUnix(), s.Node.Config.Policy); err != nil {
			writeJSON(w, statusForError(err), map[string]any{"verified": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"verified":          true,
			"exporterPeerId":    bundle.ExporterPeerID,
			"stateDigest":       bundle.StateDigest,
			"announcementCount": len(bundle.Announcements),
			"verificationClass": bundle.VerificationClass,
		})
	})
	mux.HandleFunc("/v1/p2p/telemetry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, s.Node.Telemetry())
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
