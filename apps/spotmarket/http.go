// SPDX-License-Identifier: Apache-2.0 OR MIT

package spotmarket

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/luxfi/crypto/secp256k1"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// Server wraps a Market with an optional export signer and clock source for
// dual-surface HTTP mounting (both github.com/zap-proto/zip and standard net/http).
type Server struct {
	Market *Market
	Signer *secp256k1.PrivateKey
	Now    func() int64
}

// NewServer constructs a dual-surface HTTP Server backed by m. If signer is
// nil, a fresh ephemeral secp256k1 signing key is generated for export bundles.
func NewServer(m *Market, signer *secp256k1.PrivateKey) (*Server, error) {
	if m == nil {
		return nil, errors.New("spotmarket: nil market")
	}
	if signer == nil {
		kp, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		signer = kp.PrivateKey
	}
	return &Server{
		Market: m,
		Signer: signer,
		Now:    func() int64 { return time.Now().Unix() },
	}, nil
}

func (s *Server) nowUnix() int64 {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().Unix()
}

type healthResponse struct {
	Service         string `json:"service"`
	Status          string `json:"status"`
	ProtocolVersion string `json:"protocolVersion"`
	ActiveOffers    int    `json:"activeOffers"`
	HanzoCalls      int64  `json:"hanzoCalls"`
	LedgerConserved bool   `json:"ledgerConserved"`
}

func (s *Server) buildHealth() healthResponse {
	now := s.nowUnix()
	offers := s.Market.ListOffers(now)
	return healthResponse{
		Service:         "spotmarket",
		Status:          "ok",
		ProtocolVersion: ProtocolVersion,
		ActiveOffers:    len(offers),
		HanzoCalls:      s.Market.HanzoCalls(),
		LedgerConserved: s.Market.CheckConservation() == nil,
	}
}

func (s *Server) filterOffers(model, region, jurisdiction string, maxPrice int64) []SignedOffer {
	offers := s.Market.ListOffers(s.nowUnix())
	out := make([]SignedOffer, 0, len(offers))
	for _, so := range offers {
		o := so.Offer
		if model != "" && !containsString(o.SupportedModels, model) {
			continue
		}
		if region != "" && o.Location.Region != region {
			continue
		}
		if jurisdiction != "" && o.Location.Jurisdiction != jurisdiction {
			continue
		}
		if maxPrice > 0 && o.Pricing.MicroUSDPer1MTokens > maxPrice {
			continue
		}
		out = append(out, so)
	}
	return out
}

// Mount attaches the HIP-1350 GPU spot market REST surface onto a *zip.App
// under /v1/spotmarket with zero host dependencies.
func Mount(app *zip.App, log luxlog.Logger, srv *Server) error {
	if app == nil {
		return errors.New("spotmarket: nil app")
	}
	if srv == nil || srv.Market == nil {
		return errors.New("spotmarket: nil server or market")
	}

	g := app.Group("/v1/spotmarket")
	g.Raw(http.MethodGet, "/health", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, srv.buildHealth())
	})
	g.Raw(http.MethodPost, "/offers", func(c *zip.Ctx) error {
		var so SignedOffer
		if err := json.Unmarshal(c.Body(), &so); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if err := srv.Market.RegisterOffer(so, srv.nowUnix()); err != nil {
			return c.JSON(statusForError(err), map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, so)
	})
	g.Raw(http.MethodGet, "/offers", func(c *zip.Ctx) error {
		maxPrice, _ := strconv.ParseInt(strings.TrimSpace(c.Query("max_price")), 10, 64)
		data := srv.filterOffers(
			strings.TrimSpace(c.Query("model")),
			strings.TrimSpace(c.Query("region")),
			strings.TrimSpace(c.Query("jurisdiction")),
			maxPrice,
		)
		return c.JSON(http.StatusOK, map[string]any{"data": data})
	})
	g.Raw(http.MethodPost, "/orders", func(c *zip.Ctx) error {
		var order Order
		if err := json.Unmarshal(c.Body(), &order); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if err := srv.Market.SubmitOrder(order, srv.nowUnix()); err != nil {
			return c.JSON(statusForError(err), map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, order)
	})
	g.Raw(http.MethodPost, "/bids", func(c *zip.Ctx) error {
		var sb SignedBid
		if err := json.Unmarshal(c.Body(), &sb); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if err := srv.Market.SubmitBid(sb, srv.nowUnix()); err != nil {
			return c.JSON(statusForError(err), map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusCreated, sb)
	})
	g.Raw(http.MethodPost, "/orders/:id/clear", func(c *zip.Ctx) error {
		orderID := strings.TrimSpace(c.Param("id"))
		leases, rejections, err := srv.Market.ClearOrder(orderID, srv.nowUnix())
		if err != nil {
			return c.JSON(statusForError(err), map[string]any{"error": err.Error(), "rejections": rejections})
		}
		return c.JSON(http.StatusOK, map[string]any{"leases": leases, "rejections": rejections})
	})
	g.Raw(http.MethodPost, "/leases/:id/settle", func(c *zip.Ctx) error {
		leaseID := strings.TrimSpace(c.Param("id"))
		var rep DeliveryReport
		if err := json.Unmarshal(c.Body(), &rep); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		rep.LeaseID = leaseID
		rcpt, err := srv.Market.SettleLease(leaseID, rep, srv.nowUnix())
		if err != nil {
			return c.JSON(statusForError(err), map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, rcpt)
	})
	g.Raw(http.MethodGet, "/peers", func(c *zip.Ctx) error {
		return c.JSON(http.StatusOK, srv.Market.GossipSnapshot(srv.nowUnix()))
	})
	g.Raw(http.MethodGet, "/export", func(c *zip.Ctx) error {
		bundle, err := srv.Market.ExportBundle(srv.Signer, srv.nowUnix())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, bundle)
	})

	if log != nil {
		log.Info("spotmarket mounted", "protocol", ProtocolVersion)
	}
	return nil
}

// Handler returns a pure standard-library net/http.Handler exposing the exact
// same /v1/spotmarket REST surface so independent operators can run the spot
// market without zip or any Hanzo runtime framework.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/spotmarket/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.buildHealth())
	})
	mux.HandleFunc("POST /v1/spotmarket/offers", func(w http.ResponseWriter, r *http.Request) {
		var so SignedOffer
		if err := decodeJSONBody(r, &so); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.Market.RegisterOffer(so, s.nowUnix()); err != nil {
			writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, so)
	})
	mux.HandleFunc("GET /v1/spotmarket/offers", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		maxPrice, _ := strconv.ParseInt(strings.TrimSpace(q.Get("max_price")), 10, 64)
		data := s.filterOffers(
			strings.TrimSpace(q.Get("model")),
			strings.TrimSpace(q.Get("region")),
			strings.TrimSpace(q.Get("jurisdiction")),
			maxPrice,
		)
		writeJSON(w, http.StatusOK, map[string]any{"data": data})
	})
	mux.HandleFunc("POST /v1/spotmarket/orders", func(w http.ResponseWriter, r *http.Request) {
		var order Order
		if err := decodeJSONBody(r, &order); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.Market.SubmitOrder(order, s.nowUnix()); err != nil {
			writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, order)
	})
	mux.HandleFunc("POST /v1/spotmarket/bids", func(w http.ResponseWriter, r *http.Request) {
		var sb SignedBid
		if err := decodeJSONBody(r, &sb); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.Market.SubmitBid(sb, s.nowUnix()); err != nil {
			writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, sb)
	})
	mux.HandleFunc("POST /v1/spotmarket/orders/{id}/clear", func(w http.ResponseWriter, r *http.Request) {
		orderID := strings.TrimSpace(r.PathValue("id"))
		leases, rejections, err := s.Market.ClearOrder(orderID, s.nowUnix())
		if err != nil {
			writeJSON(w, statusForError(err), map[string]any{"error": err.Error(), "rejections": rejections})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"leases": leases, "rejections": rejections})
	})
	mux.HandleFunc("POST /v1/spotmarket/leases/{id}/settle", func(w http.ResponseWriter, r *http.Request) {
		leaseID := strings.TrimSpace(r.PathValue("id"))
		var rep DeliveryReport
		if err := decodeJSONBody(r, &rep); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		rep.LeaseID = leaseID
		rcpt, err := s.Market.SettleLease(leaseID, rep, s.nowUnix())
		if err != nil {
			writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rcpt)
	})
	mux.HandleFunc("GET /v1/spotmarket/peers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Market.GossipSnapshot(s.nowUnix()))
	})
	mux.HandleFunc("GET /v1/spotmarket/export", func(w http.ResponseWriter, r *http.Request) {
		bundle, err := s.Market.ExportBundle(s.Signer, s.nowUnix())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, bundle)
	})
	return mux
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrHighSMalleableSignature), errors.Is(err, ErrCommitmentMismatch):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInsufficientBalance), errors.Is(err, ErrInsufficientBond):
		return http.StatusPaymentRequired
	case errors.Is(err, ErrSybilBidLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrNoEligibleBids), errors.Is(err, ErrCapacityOverclaim), errors.Is(err, ErrLeaseAlreadySettled), errors.Is(err, ErrReplayNonce):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}
