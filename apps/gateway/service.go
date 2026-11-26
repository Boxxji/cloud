// SPDX-License-Identifier: Apache-2.0 OR MIT

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// Mount exposes the OpenAI-compatible Enso gateway and stateless scheduling
// HTTP surface on app under /v1. It imports only zip, luxlog, the Go standard
// library, and this package — never its host.
func Mount(app *zip.App, log luxlog.Logger, gw *Gateway) error {
	if app == nil {
		return errors.New("gateway: nil zip app")
	}
	if gw == nil {
		var err error
		gw, err = NewGateway(GatewayConfig{
			GatewayID:    "enso-community-default",
			OperatorName: "Community Default Gateway",
			OperatorType: OperatorTypeCommunity,
			Strategy:     StrategyWeightedSLOScore,
		})
		if err != nil {
			return err
		}
	}

	o := zipOps{gw: gw}
	v1 := app.Group("/v1")
	v1.Get("/models", o.models)
	v1.Post("/chat/completions", o.chatCompletions)

	gwGroup := v1.Group("/gateway")
	gwGroup.Get("/health", o.health)
	gwGroup.Get("/providers", o.providers)
	gwGroup.Post("/quotes", o.quotes)
	gwGroup.Post("/receipts/verify", o.verifyReceipt)
	gwGroup.Get("/export", o.exportBundle)

	if log != nil {
		log.Info("gateway mounted",
			"gatewayId", gw.GatewayID(),
			"operatorType", gw.OperatorType(),
			"protocol", ProtocolVersion,
			"strategy", string(gw.Config().Strategy),
		)
	}
	return nil
}

type zipOps struct {
	gw *Gateway
}

type emptyIn struct{}

// HealthResponse summarizes live gateway status, operator identity, and call counts.
type HealthResponse struct {
	Service         string `json:"service"`
	GatewayID       string `json:"gatewayId"`
	OperatorType    string `json:"operatorType"`
	OperatorAddress string `json:"operatorAddress"`
	ProtocolVersion string `json:"protocolVersion"`
	Strategy        string `json:"strategy"`
	Status          string `json:"status"`
	GatewayFeeBps   uint64 `json:"gatewayFeeBps"`
	Calls           int64  `json:"calls"`
}

// ProvidersResponse lists verified workers currently known to this gateway.
type ProvidersResponse struct {
	GatewayID       string         `json:"gatewayId"`
	ProtocolVersion string         `json:"protocolVersion"`
	Providers       []WorkerRecord `json:"providers"`
}

func (o zipOps) health(_ context.Context, _ *emptyIn) (*HealthResponse, error) {
	if o.gw.IsDisabled() {
		return nil, mapError(ErrGatewayDisabled)
	}
	cfg := o.gw.Config()
	return &HealthResponse{
		Service:         "enso-gateway",
		GatewayID:       o.gw.GatewayID(),
		OperatorType:    o.gw.OperatorType(),
		OperatorAddress: o.gw.Address(),
		ProtocolVersion: ProtocolVersion,
		Strategy:        string(cfg.Strategy),
		Status:          "ok",
		GatewayFeeBps:   cfg.GatewayFeeBps,
		Calls:           o.gw.Calls(),
	}, nil
}

func (o zipOps) models(ctx context.Context, _ *emptyIn) (*ModelsListResponse, error) {
	res, err := o.gw.ListModels(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return res, nil
}

func (o zipOps) chatCompletions(ctx context.Context, in *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	if in == nil {
		return nil, mapError(ErrInvalidRequest)
	}
	res, err := o.gw.ChatCompletions(ctx, *in)
	if err != nil {
		return nil, mapError(err)
	}
	return res, nil
}

func (o zipOps) providers(ctx context.Context, _ *emptyIn) (*ProvidersResponse, error) {
	list, err := o.gw.ListProviders(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return &ProvidersResponse{
		GatewayID:       o.gw.GatewayID(),
		ProtocolVersion: ProtocolVersion,
		Providers:       list,
	}, nil
}

func (o zipOps) quotes(ctx context.Context, in *QuotesQuery) (*QuotesResponse, error) {
	if in == nil {
		return nil, mapError(ErrInvalidRequest)
	}
	res, err := o.gw.FetchQuotes(ctx, *in)
	if err != nil {
		return nil, mapError(err)
	}
	return res, nil
}

func (o zipOps) verifyReceipt(_ context.Context, in *VerifyReceiptRequest) (*VerifyReceiptResponse, error) {
	if in == nil {
		return nil, mapError(ErrInvalidRequest)
	}
	res, err := o.gw.VerifyReceipt(*in)
	if err != nil {
		return nil, mapError(err)
	}
	return res, nil
}

func (o zipOps) exportBundle(_ context.Context, _ *emptyIn) (*GatewayExportBundle, error) {
	if o.gw.IsDisabled() {
		return nil, mapError(ErrGatewayDisabled)
	}
	b, err := o.gw.ExportBundle()
	if err != nil {
		return nil, mapError(err)
	}
	return b, nil
}

func httpStatusForError(err error) int {
	switch {
	case errors.Is(err, ErrGatewayDisabled),
		errors.Is(err, ErrNoHealthyProviders),
		errors.Is(err, ErrProviderUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrInvalidSignature),
		errors.Is(err, ErrSignerMismatch):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalidQuote),
		errors.Is(err, ErrQuoteExpired),
		errors.Is(err, ErrInvalidReceipt),
		errors.Is(err, ErrOutputHashMismatch),
		errors.Is(err, ErrDirectoryCorrupted):
		return http.StatusUnprocessableEntity
	case errors.Is(err, ErrReplayNonce):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func mapError(err error) error {
	return zip.Errorf(httpStatusForError(err), "%s", err.Error())
}

// NewHTTPHandler builds a standard net/http handler serving the identical
// OpenAI-compatible and gateway protocol endpoints over real TCP/loopback HTTP.
func NewHTTPHandler(gw *Gateway) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		res, err := gw.ListModels(r.Context())
		if err != nil {
			writeErrorJSON(w, err)
			return
		}
		w.Header().Set("X-Enso-Gateway-ID", gw.GatewayID())
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req ChatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorJSON(w, ErrInvalidRequest)
			return
		}
		res, err := gw.ChatCompletions(r.Context(), req)
		if err != nil {
			writeErrorJSON(w, err)
			return
		}
		w.Header().Set("X-Enso-Gateway-ID", gw.GatewayID())
		if res.EnsoReceipt != nil {
			w.Header().Set("X-Enso-Provider-ID", res.EnsoReceipt.ProviderID)
			w.Header().Set("X-Enso-Receipt-ID", res.EnsoReceipt.ReceiptID)
			w.Header().Set("X-Enso-Quote-Hash", res.EnsoReceipt.QuoteHash)
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/v1/gateway/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if gw.IsDisabled() {
			writeErrorJSON(w, ErrGatewayDisabled)
			return
		}
		cfg := gw.Config()
		writeJSON(w, http.StatusOK, HealthResponse{
			Service:         "enso-gateway",
			GatewayID:       gw.GatewayID(),
			OperatorType:    gw.OperatorType(),
			OperatorAddress: gw.Address(),
			ProtocolVersion: ProtocolVersion,
			Strategy:        string(cfg.Strategy),
			Status:          "ok",
			GatewayFeeBps:   cfg.GatewayFeeBps,
			Calls:           gw.Calls(),
		})
	})

	mux.HandleFunc("/v1/gateway/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list, err := gw.ListProviders(r.Context())
		if err != nil {
			writeErrorJSON(w, err)
			return
		}
		writeJSON(w, http.StatusOK, ProvidersResponse{
			GatewayID:       gw.GatewayID(),
			ProtocolVersion: ProtocolVersion,
			Providers:       list,
		})
	})

	mux.HandleFunc("/v1/gateway/quotes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var q QuotesQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			writeErrorJSON(w, ErrInvalidRequest)
			return
		}
		res, err := gw.FetchQuotes(r.Context(), q)
		if err != nil {
			writeErrorJSON(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/v1/gateway/receipts/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var in VerifyReceiptRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErrorJSON(w, ErrInvalidRequest)
			return
		}
		res, err := gw.VerifyReceipt(in)
		if err != nil {
			writeErrorJSON(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/v1/gateway/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if gw.IsDisabled() {
			writeErrorJSON(w, ErrGatewayDisabled)
			return
		}
		b, err := gw.ExportBundle()
		if err != nil {
			writeErrorJSON(w, err)
			return
		}
		writeJSON(w, http.StatusOK, b)
	})

	return mux
}

func writeErrorJSON(w http.ResponseWriter, err error) {
	status := httpStatusForError(err)
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": err.Error(),
			"code":    status,
		},
	})
}

// StartLoopbackServer launches gw on an ephemeral loopback TCP HTTP server.
func StartLoopbackServer(gw *Gateway) *httptest.Server {
	return httptest.NewServer(NewHTTPHandler(gw))
}
