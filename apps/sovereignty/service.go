// SPDX-License-Identifier: Apache-2.0 OR MIT

package sovereignty

import (
	"context"
	"errors"
	"net/http"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

// Mount exposes the HIP-1351 full sovereignty and network exit HTTP surface on
// app under /v1/sovereignty. It imports only zip, luxlog, the Go standard
// library, and this package — never its host.
func Mount(app *zip.App, log luxlog.Logger, coord *Coordinator) error {
	if app == nil {
		return errors.New("sovereignty: nil app")
	}
	if coord == nil {
		coord = NewCoordinator(DefaultDomain())
	}
	o := httpOps{coord: coord}
	g := app.Group("/v1/sovereignty")
	g.Get("/health", o.health)
	g.Post("/drill/run", o.runDrill)
	g.Get("/drill/latest", o.latestDrill)
	g.Post("/regimes/run", o.runRegimes)
	g.Get("/fork/export", o.exportFork)
	g.Post("/fork/verify", o.verifyFork)

	if log != nil {
		dom := coord.Domain()
		log.Info("sovereignty mounted", "protocol", ProtocolVersion, "chainId", dom.ChainID)
	}
	return nil
}

type httpOps struct {
	coord *Coordinator
}

type emptyIn struct{}

// HealthOut reports sovereignty harness status and drill history.
type HealthOut struct {
	Service         string `json:"service"`
	ProtocolVersion string `json:"protocolVersion"`
	Status          string `json:"status"`
	ChainID         uint64 `json:"chainId"`
	DrillsCompleted int64  `json:"drillsCompleted"`
}

func (o httpOps) health(_ context.Context, _ *emptyIn) (*HealthOut, error) {
	dom := o.coord.Domain()
	return &HealthOut{
		Service:         "sovereignty",
		ProtocolVersion: ProtocolVersion,
		Status:          "ok",
		ChainID:         dom.ChainID,
		DrillsCompleted: o.coord.RunsCount(),
	}, nil
}

func (o httpOps) runDrill(_ context.Context, _ *emptyIn) (*NetworkExitReport, error) {
	rep, _, err := o.coord.RunDrill()
	if err != nil {
		return nil, mapError(err)
	}
	return rep, nil
}

func (o httpOps) latestDrill(_ context.Context, _ *emptyIn) (*NetworkExitReport, error) {
	rep, ok := o.coord.LatestReport()
	if !ok {
		return nil, mapError(ErrNotFound)
	}
	return rep, nil
}

// RegimesIn configures the number of trials per negative/boundary regime.
type RegimesIn struct {
	Trials int `json:"trials"`
}

// RegimesOut returns all three honest negative and boundary regime results.
type RegimesOut struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Regimes         []NegativeRegimeResult `json:"regimes"`
}

func (o httpOps) runRegimes(_ context.Context, in *RegimesIn) (*RegimesOut, error) {
	trials := 25
	if in != nil && in.Trials > 0 {
		trials = in.Trials
	}
	res, err := RunNegativeAndBoundaryRegimes(o.coord.Domain(), trials)
	if err != nil {
		return nil, mapError(err)
	}
	return &RegimesOut{
		ProtocolVersion: ProtocolVersion,
		Regimes:         res,
	}, nil
}

func (o httpOps) exportFork(_ context.Context, _ *emptyIn) (*NetworkForkBundle, error) {
	fork, ok := o.coord.LatestForkBundle()
	if !ok {
		var err error
		_, fork, err = o.coord.RunDrill()
		if err != nil {
			return nil, mapError(err)
		}
	}
	return fork, nil
}

// ForkVerifyOut summarizes offline cryptographic verification of a NetworkForkBundle.
type ForkVerifyOut struct {
	Valid             bool   `json:"valid"`
	ProtocolVersion   string `json:"protocolVersion"`
	OperatorID        string `json:"operatorId"`
	BundleSHA256      string `json:"bundleSha256"`
	ProviderCount     int    `json:"providerCount"`
	ModelCount        int    `json:"modelCount"`
	LedgerEntries     int    `json:"ledgerEntries"`
	VaultSnapshotSize int    `json:"vaultSnapshotSize"`
}

func (o httpOps) verifyFork(_ context.Context, in *NetworkForkBundle) (*ForkVerifyOut, error) {
	if in == nil {
		return nil, mapError(ErrInvalidRequest)
	}
	if err := VerifyForkBundleOffline(o.coord.Domain(), *in); err != nil {
		return nil, mapError(err)
	}
	return &ForkVerifyOut{
		Valid:             true,
		ProtocolVersion:   in.ProtocolVersion,
		OperatorID:        in.OperatorID,
		BundleSHA256:      in.BundleSHA256,
		ProviderCount:     len(in.Providers),
		ModelCount:        len(in.Models),
		LedgerEntries:     len(in.SettlementLedger),
		VaultSnapshotSize: len(in.EncryptedVault),
	}, nil
}

func mapError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return zip.Errorf(http.StatusNotFound, "%s", err.Error())
	case errors.Is(err, ErrInvalidSignature),
		errors.Is(err, ErrSignerMismatch),
		errors.Is(err, ErrUnauthorizedDataAccess):
		return zip.Errorf(http.StatusUnauthorized, "%s", err.Error())
	case errors.Is(err, ErrForkBundleCorrupted),
		errors.Is(err, ErrModelDigestMismatch),
		errors.Is(err, ErrInvalidReceipt):
		return zip.Errorf(http.StatusUnprocessableEntity, "%s", err.Error())
	case errors.Is(err, ErrHanzoHostBlocked),
		errors.Is(err, ErrHanzoPlaneOffline),
		errors.Is(err, ErrBootstrapQuorumLost):
		return zip.Errorf(http.StatusServiceUnavailable, "%s", err.Error())
	case errors.Is(err, ErrReplayDetected):
		return zip.Errorf(http.StatusConflict, "%s", err.Error())
	case errors.Is(err, ErrInsufficientBalance):
		return zip.Errorf(http.StatusPaymentRequired, "%s", err.Error())
	default:
		return zip.Errorf(http.StatusBadRequest, "%s", err.Error())
	}
}
