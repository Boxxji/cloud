package supply

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/bus"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// reader is the one metric reader every test in this package reads, installed
// before any instrument exists so the lazily created instruments bind to it.
var reader = sdkmetric.NewManualReader()

func TestMain(m *testing.M) {
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	m.Run()
}

// heard records every pulse this package announces, and resets the per-process
// memory of what was already said, so each test starts from silence.
func heard(t *testing.T) func() []bus.Pulse {
	t.Helper()
	var mu sync.Mutex
	var got []bus.Pulse
	t.Cleanup(SetAnnounce(func(p bus.Pulse) error {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
		return nil
	}))
	forget()
	return func() []bus.Pulse {
		mu.Lock()
		defer mu.Unlock()
		return append([]bus.Pulse(nil), got...)
	}
}

// A stop is its own class: one code, a layer, a provider — and none of the codes a
// client already branches on for capacity, sign-in or money.
func TestAStopRendersAsBudgetExhaustedNamingItsLayer(t *testing.T) {
	ex := &Exhausted{Provider: "cloudflare", Layer: DurableObjects, Upstream: 429,
		Msg: "Exceeded the account's spending cap for Durable Objects."}

	he := ex.HTTPError()
	if he.Code != Code || Code != "budget_exhausted" {
		t.Fatalf("code = %q, want budget_exhausted", he.Code)
	}
	if he.Status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (the provider cannot serve; the caller owes nothing)", he.Status)
	}
	if he.Detail["layer"] != "durable_objects" || he.Detail["provider"] != "cloudflare" {
		t.Fatalf("detail = %v, want layer=durable_objects provider=cloudflare", he.Detail)
	}
	if !strings.Contains(he.Msg, "Durable Objects") || !strings.Contains(he.Msg, "spending cap") {
		t.Fatalf("message %q should name the layer and carry the provider's own sentence", he.Msg)
	}
	for _, other := range []string{"", "insufficient_balance", "spend_cap_exceeded", "rate_limited", "unauthorized", "forbidden"} {
		if he.Code == other {
			t.Fatalf("budget_exhausted collides with %q", other)
		}
	}
}

// A stop survives being wrapped, and is found by the sentinel or by its type.
func TestAStopIsFoundThroughAWrap(t *testing.T) {
	ex := &Exhausted{Provider: "cloudflare", Layer: WorkersAI}
	err := fmt.Errorf("workers ai run: %w", ex)
	if !errors.Is(err, ErrExhausted) {
		t.Fatal("errors.Is(wrapped, ErrExhausted) = false")
	}
	got, ok := As(err)
	if !ok || got.Layer != WorkersAI {
		t.Fatalf("As(wrapped) = %v, %v; want the workers_ai stop", got, ok)
	}
	if _, ok := As(errors.New("capacity temporarily exceeded")); ok {
		t.Fatal("an ordinary error read as a budget stop")
	}
	if !strings.Contains(err.Error(), "budget_exhausted") {
		t.Fatalf("Error() = %q, want the code in it for a log reader", err.Error())
	}
}

// The threshold is the operator's: a percentage below the hard cap, 80 unless set,
// and a value that is not a percentage below 100 falls back rather than silencing
// the warning or firing it on every reading.
func TestTheWarnThresholdIsConfigurable(t *testing.T) {
	for _, c := range []struct {
		env  string
		want int
	}{
		{"", 80}, {"50", 50}, {"95", 95}, {"0", 80}, {"100", 80}, {"-5", 80}, {"eighty", 80},
	} {
		t.Setenv(WarnEnv, c.env)
		if got := WarnPct(); got != c.want {
			t.Errorf("%s=%q: WarnPct() = %d, want %d", WarnEnv, c.env, got, c.want)
		}
	}
}

// Below the threshold nothing is said; at it, one warning names the layer and how
// much of the cap is spent; past the cap the layer is exhausted. Each is said once
// per window, not once per reading.
func TestAReadingWarnsAtTheThresholdBelowTheCap(t *testing.T) {
	pulses := heard(t)
	t.Setenv(WarnEnv, "75")

	r := Reading{Provider: "cloudflare", Layer: Workers, Org: "acme", Used: 7000, Limit: 10000}
	if lv := Observe(context.Background(), r); lv != Below {
		t.Fatalf("70%% of the cap: level %v, want Below", lv)
	}
	if n := len(pulses()); n != 0 {
		t.Fatalf("70%% of the cap with a 75%% threshold announced %d pulses, want 0", n)
	}

	r.Used = 8000
	if lv := Observe(context.Background(), r); lv != Warn {
		t.Fatalf("80%% of the cap: level %v, want Warn", lv)
	}
	got := pulses()
	if len(got) != 1 {
		t.Fatalf("crossing the threshold announced %d pulses, want 1", len(got))
	}
	p := got[0]
	if p.Kind != "supply" || p.Org != "acme" || !strings.Contains(p.Title, "Workers") || !strings.Contains(p.Title, "80%") {
		t.Fatalf("warning pulse = %+v, want kind supply, org acme, a title naming Workers at 80%%", p)
	}

	// A second reading inside the window is not a second page.
	r.Used = 8500
	Observe(context.Background(), r)
	if n := len(pulses()); n != 1 {
		t.Fatalf("a repeat reading announced again: %d pulses, want 1", n)
	}

	// Reaching the cap is a different fact and is said at once.
	r.Used = 10000
	if lv := Observe(context.Background(), r); lv != AtCap {
		t.Fatalf("100%% of the cap: level %v, want AtCap", lv)
	}
	if n := len(pulses()); n != 2 {
		t.Fatalf("reaching the cap announced %d pulses in all, want 2", n)
	}
}

// A reading with no cap says nothing: there is no ceiling to be near.
func TestAReadingWithNoCapIsNotAWarning(t *testing.T) {
	pulses := heard(t)
	if lv := Observe(context.Background(), Reading{Provider: "cloudflare", Layer: Workers, Used: 5, Limit: 0}); lv != Below {
		t.Fatalf("no cap: level %v, want Below", lv)
	}
	if n := len(pulses()); n != 0 {
		t.Fatalf("no cap announced %d pulses, want 0", n)
	}
}

// The window is a window: after it passes, a layer still past the threshold is
// said again, so a reader who missed the first still hears it.
func TestAWarningRepeatsAfterItsWindow(t *testing.T) {
	pulses := heard(t)
	at := time.Unix(1_800_000_000, 0)
	prev := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = prev })

	r := Reading{Provider: "cloudflare", Layer: DurableObjects, Org: "acme", Used: 90, Limit: 100}
	Observe(context.Background(), r)
	at = at.Add(Every - time.Second)
	Observe(context.Background(), r)
	if n := len(pulses()); n != 1 {
		t.Fatalf("inside the window: %d pulses, want 1", n)
	}
	at = at.Add(2 * time.Second)
	Observe(context.Background(), r)
	if n := len(pulses()); n != 2 {
		t.Fatalf("after the window: %d pulses, want 2", n)
	}
}

// Report puts a stop on the pulse and on the counter, once per window per layer.
func TestReportAnnouncesAStopOnce(t *testing.T) {
	pulses := heard(t)
	ex := &Exhausted{Provider: "cloudflare", Layer: WorkersAI, Org: "acme", Upstream: 429,
		Msg: "You have used up your daily free allocation of 10,000 neurons."}
	Report(context.Background(), ex)
	Report(context.Background(), ex)
	got := pulses()
	if len(got) != 1 {
		t.Fatalf("two reports of one stop announced %d pulses, want 1", len(got))
	}
	if !strings.Contains(got[0].Title, "Workers AI") || !strings.Contains(got[0].Title, "exhausted") {
		t.Fatalf("stop pulse title = %q, want it to name Workers AI and say exhausted", got[0].Title)
	}
	if got[0].Org != "acme" {
		t.Fatalf("stop pulse org = %q, want acme", got[0].Org)
	}
	if n := counted(t, "hanzo_provider_budget_exhausted_total", "cloudflare", "workers_ai"); n != 2 {
		t.Fatalf("hanzo_provider_budget_exhausted_total{cloudflare,workers_ai} = %d, want 2 (the counter counts every stop; only the pulse is folded)", n)
	}
}

// The platform's own stops are the platform's: an empty org pages as admin.
func TestAPlatformStopPagesTheAdminOrg(t *testing.T) {
	pulses := heard(t)
	Report(context.Background(), &Exhausted{Provider: "hanzo", Layer: Model})
	if got := pulses(); len(got) != 1 || got[0].Org != "admin" {
		t.Fatalf("platform stop pulses = %+v, want one for org admin", got)
	}
}

// The gauge carries the used share and the threshold beside it, so one alert rule
// compares the two and follows the threshold the deployment sets.
func TestTheGaugesCarryTheShareAndTheThreshold(t *testing.T) {
	heard(t)
	t.Setenv(WarnEnv, "60")
	Observe(context.Background(), Reading{Provider: "cloudflare", Layer: Workers, Org: "gauge-org", Used: 30, Limit: 40})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	share, warn := -1.0, -1.0
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[float64])
			if !ok {
				continue
			}
			for _, dp := range g.DataPoints {
				switch m.Name {
				case "hanzo_provider_budget_used_ratio":
					if v, _ := dp.Attributes.Value("org"); v.AsString() == "gauge-org" {
						share = dp.Value
					}
				case "hanzo_provider_budget_warn_ratio":
					warn = dp.Value
				}
			}
		}
	}
	if share != 0.75 {
		t.Fatalf("hanzo_provider_budget_used_ratio = %v, want 0.75", share)
	}
	if warn != 0.60 {
		t.Fatalf("hanzo_provider_budget_warn_ratio = %v, want 0.60", warn)
	}
}

// counted reads one counter series' total.
func counted(t *testing.T, name, provider, layer string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				p, _ := dp.Attributes.Value("provider")
				l, _ := dp.Attributes.Value("layer")
				if p.AsString() == provider && l.AsString() == layer {
					return dp.Value
				}
			}
		}
	}
	return 0
}
