module github.com/hanzoai/cloud

go 1.27.1

// Dependencies will be added as subsystems are mounted per HIP-0106.

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/hanzoai/account v0.3.3
	github.com/hanzoai/ai v1.833.384
	github.com/hanzoai/authz v1.10.47
	github.com/hanzoai/cek v0.2.11
	github.com/hanzoai/commerce v1.50.247
	github.com/hanzoai/decimal v0.1.2
	github.com/hanzoai/go-openai v1.41.0
	github.com/hanzoai/goa v1.0.0
	github.com/hanzoai/ha v0.2.0
	github.com/hanzoai/iam v1.34.192
	github.com/hanzoai/money v0.2.5
	github.com/hanzoai/namespace v1.2.0
	github.com/hanzoai/orm v0.6.45
	github.com/hanzoai/sqlite v0.5.10
	github.com/hanzoai/tasks v1.53.11
	github.com/hanzoai/vfs v0.6.6
	github.com/hanzokv/go/v9 v9.22.0
	github.com/hanzos3/go v1.0.3
	github.com/jackc/pgx/v5 v5.11.0
	github.com/lib/pq v1.12.3
	github.com/luxfi/crypto v1.20.13
	github.com/luxfi/kms v1.12.27
	github.com/luxfi/log v1.6.2
	github.com/luxfi/zapdb v1.10.6
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/prometheus/client_golang v1.23.2
	github.com/valyala/fasthttp v1.74.0
	github.com/vulcand/oxy/v2 v2.0.0-00010101000000-000000000000
	github.com/zap-proto/fiber/v3 v3.2.1
	github.com/zap-proto/go v1.8.3
	github.com/zap-proto/http v0.3.12
	github.com/zap-proto/mcp v1.0.6
	github.com/zap-proto/md v0.1.0
	github.com/zap-proto/zip v1.37.44
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/metric v1.44.0
	go.opentelemetry.io/otel/sdk v1.44.0
	go.opentelemetry.io/otel/sdk/metric v1.44.0
	go.opentelemetry.io/otel/trace v1.44.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.50.0
	k8s.io/apimachinery v0.36.2
	sigs.k8s.io/yaml v1.6.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/HdrHistogram/hdrhistogram-go v1.2.0 // indirect
	github.com/alexedwards/argon2id v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dgraph-io/ristretto/v2 v2.4.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2/v2 v2.5.2 // indirect
	github.com/dop251/goja v0.0.0-20260906210903-70ad66ec7ce4 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/evanw/esbuild v0.28.2 // indirect
	github.com/fasthttp/websocket v1.5.12 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-python/gpython v0.2.0 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.17.4 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/pprof v0.0.0-20260402051712-545e8a4df936 // indirect
	github.com/google/uuid v1.6.1-0.20241114170450-2d3c2a9cc518 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/hanzoai/csqlite v0.1.2 // indirect
	github.com/hanzoai/dbx v1.17.4 // indirect
	github.com/hanzoai/outbound v1.0.0 // indirect
	github.com/hanzoai/sqlcipher v0.1.1 // indirect
	github.com/hanzos3/crc64nvme v1.1.2 // indirect
	github.com/hanzos3/md5-simd v1.1.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/luxfi/accel v1.2.4 // indirect
	github.com/luxfi/age v1.6.0 // indirect
	github.com/luxfi/cache v1.3.5 // indirect
	github.com/luxfi/container v0.2.2 // indirect
	github.com/luxfi/ids v1.3.2 // indirect
	github.com/luxfi/math v1.5.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.2.1 // indirect
	github.com/luxfi/metric v1.11.2 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/zap v1.2.9 // indirect
	github.com/luxwallet/connect/go v0.1.4 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/molecule-man/go-brrr v1.0.1 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oasisprotocol/curve25519-voi v0.0.0-20251114093237-2ab5a27a1729 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/savsgio/gotils v0.0.0-20240704082632-aef3928b8a38 // indirect
	github.com/segmentio/fasthash v1.0.3 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/log v0.20.0 // indirect
	go.opentelemetry.io/otel/sdk/log v0.20.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20260529124908-c761662dc8c9 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/utils v0.0.0-20260319190234-28399d86e0b5 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.51.0 // indirect
)

replace github.com/apache/thrift => github.com/apache/thrift v0.16.0

replace github.com/uber/jaeger-client-go => github.com/uber/jaeger-client-go v2.28.0+incompatible

replace github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20200324110947-a37a7636d23e

replace github.com/mailgun/minheap => github.com/containous/minheap v0.0.0-20190809180810-6e71eb837595

replace github.com/vulcand/oxy/v2 => github.com/traefik/oxy/v2 v2.0.0-20260126093803-fb11d60e0fdf

// Phantom-version fix: some transitive dep requires the non-existent
// release (drop-in, package sqlite3) via a VERSIONED replace (left side pins the
// phantom) so Go never tries to read v2.0.3's go.mod during module-graph load —
// modernc). Every cloud store imports the fork, never modernc directly, so the
// "sqlite" driver is registered exactly once.

exclude github.com/ugorji/go v0.0.0-20171122102828-84cb69a8af83
