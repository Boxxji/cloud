// SPDX-License-Identifier: Apache-2.0

package sandboxpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxPolicyRules bounds total rules across all three domains per policy.
	MaxPolicyRules = 4096
	// MaxArgFiltersPerRule bounds argument predicates attached to a single syscall rule.
	MaxArgFiltersPerRule = 6
	// MaxSyscallNumber bounds valid Linux syscall numbers for validation and BPF emission.
	MaxSyscallNumber = 1024
	// MaxLineageDepth bounds process lineage slices to prevent unbounded memory growth.
	MaxLineageDepth = 64
	// MaxFieldLen bounds identifier and pattern lengths.
	MaxFieldLen = 512

	// ErrnoEPERM is POSIX EPERM (Operation not permitted) returned under EnforceDeny.
	ErrnoEPERM = 1
	// SignalSIGKILL is POSIX SIGKILL (9) emitted under EnforceSigkill.
	SignalSIGKILL = 9
)

// Sentinel errors returned by policy validation, compilation, and engine operations.
var (
	ErrInvalidPolicy       = errors.New("sandboxpolicy: invalid policy")
	ErrPolicyConflict      = errors.New("sandboxpolicy: conflicting rules at identical priority and match key")
	ErrPolicyNotFound      = errors.New("sandboxpolicy: policy not found")
	ErrSandboxNotFound     = errors.New("sandboxpolicy: sandbox not found")
	ErrTenantLimitExceeded = errors.New("sandboxpolicy: tenant capacity limit exceeded")
	ErrRuleLimitExceeded   = errors.New("sandboxpolicy: policy rule limit exceeded")
)

// EnforcementMode determines how policy violations are handled.
type EnforcementMode string

const (
	// ModeAuditOnly logs violations as AUDIT_ALERT without blocking execution.
	ModeAuditOnly EnforcementMode = "audit_only"
	// ModeEnforceDeny synchronously blocks violating operations with EPERM (Override).
	ModeEnforceDeny EnforcementMode = "enforce_deny"
	// ModeEnforceSigkill synchronously terminates the violating process (Tetragon Sigkill).
	ModeEnforceSigkill EnforcementMode = "enforce_sigkill"
)

// ParseEnforcementMode validates and normalizes an EnforcementMode string.
func ParseEnforcementMode(raw string) (EnforcementMode, error) {
	switch EnforcementMode(strings.ToLower(strings.TrimSpace(raw))) {
	case ModeAuditOnly:
		return ModeAuditOnly, nil
	case ModeEnforceDeny:
		return ModeEnforceDeny, nil
	case ModeEnforceSigkill:
		return ModeEnforceSigkill, nil
	default:
		return "", fmt.Errorf("%w: unsupported enforcement mode %q", ErrInvalidPolicy, raw)
	}
}

func modeSeverity(m EnforcementMode) int {
	switch m {
	case ModeEnforceSigkill:
		return 3
	case ModeEnforceDeny:
		return 2
	case ModeAuditOnly:
		return 1
	default:
		return 0
	}
}

// Decision represents the concrete runtime verdict emitted for an evaluated event.
type Decision string

const (
	DecisionAllow      Decision = "ALLOW"
	DecisionAuditAlert Decision = "AUDIT_ALERT"
	DecisionDeny       Decision = "DENY"
	DecisionSigkill    Decision = "SIGKILL"
)

// Blocked reports whether the decision prevents the operation from executing.
func (d Decision) Blocked() bool {
	return d == DecisionDeny || d == DecisionSigkill
}

// Domain identifies the runtime enforcement domain.
type Domain string

const (
	DomainSyscall Domain = "syscall"
	DomainProcess Domain = "process"
	DomainNetwork Domain = "network"
)

// RuleEffect determines whether a matching rule permits or forbids an operation.
type RuleEffect string

const (
	EffectAllow RuleEffect = "allow"
	EffectDeny  RuleEffect = "deny"
)

// ArgOp specifies a comparison operator for a syscall 64-bit argument filter.
type ArgOp string

const (
	ArgOpEqual     ArgOp = "eq"
	ArgOpNotEqual  ArgOp = "ne"
	ArgOpMaskAny   ArgOp = "mask_any" // (arg & value) != 0
	ArgOpMaskAll   ArgOp = "mask_all" // (arg & value) == value
	ArgOpGreaterEq ArgOp = "ge"
	ArgOpLessEq    ArgOp = "le"
)

// SyscallArgFilter matches one of the 6 syscall argument registers (index 0..5).
type SyscallArgFilter struct {
	// Index selects the syscall argument register (0..5).
	Index uint8 `json:"index"`
	// Op selects the comparison operator ("eq", "ne", "mask_any", "mask_all", "ge", "le").
	Op ArgOp `json:"op"`
	// Value is the 64-bit immediate operand compared against the argument register.
	Value uint64 `json:"value"`
}

// Matches evaluates the argument filter against a 6-register syscall argument vector.
func (f SyscallArgFilter) Matches(args [6]uint64) bool {
	if f.Index > 5 {
		return false
	}
	v := args[f.Index]
	switch f.Op {
	case ArgOpEqual:
		return v == f.Value
	case ArgOpNotEqual:
		return v != f.Value
	case ArgOpMaskAny:
		return (v & f.Value) != 0
	case ArgOpMaskAll:
		return (v & f.Value) == f.Value
	case ArgOpGreaterEq:
		return v >= f.Value
	case ArgOpLessEq:
		return v <= f.Value
	default:
		return false
	}
}

// SyscallRule defines an allow or deny rule over Linux syscalls and optional arguments.
type SyscallRule struct {
	// ID uniquely identifies the rule within the policy.
	ID string `json:"id"`
	// Priority determines deterministic evaluation order (higher runs first).
	Priority int `json:"priority"`
	// Effect is "allow" or "deny".
	Effect RuleEffect `json:"effect"`
	// Action optionally overrides the policy mode when Effect is "deny".
	Action EnforcementMode `json:"action,omitempty"`
	// SyscallName is the canonical Linux x86_64 syscall name (e.g., "ptrace", "openat").
	SyscallName string `json:"syscallName,omitempty"`
	// SyscallNumber optionally specifies the numeric syscall ID (-1 or omitted when using SyscallName).
	SyscallNumber *int `json:"syscallNumber,omitempty"`
	// ArgFilters optionally restricts matches by syscall argument register predicates.
	ArgFilters []SyscallArgFilter `json:"argFilters,omitempty"`
	// AuditOnAllow controls whether allow hits emit userspace audit events (false = in-kernel fast-path).
	AuditOnAllow bool `json:"auditOnAllow,omitempty"`
	// Reason explains the security rationale recorded in audit events.
	Reason string `json:"reason,omitempty"`
}

// ProcessRule defines an allow or deny rule over process executions.
type ProcessRule struct {
	// ID uniquely identifies the rule within the policy.
	ID string `json:"id"`
	// Priority determines deterministic evaluation order (higher runs first).
	Priority int `json:"priority"`
	// Effect is "allow" or "deny".
	Effect RuleEffect `json:"effect"`
	// Action optionally overrides the policy mode when Effect is "deny".
	Action EnforcementMode `json:"action,omitempty"`
	// BinaryExact matches an exact canonical normalized binary path (e.g., "/usr/bin/sudo").
	BinaryExact string `json:"binaryExact,omitempty"`
	// BinaryPrefix matches a canonical path directory prefix (e.g., "/usr/bin" matches "/usr/bin/go", not "/usr/bin2/x").
	BinaryPrefix string `json:"binaryPrefix,omitempty"`
	// ArgContains optionally requires at least one argv element to contain this substring.
	ArgContains string `json:"argContains,omitempty"`
	// ArgRegex optionally matches the joined argv string using RE2 regular expression syntax.
	ArgRegex string `json:"argRegex,omitempty"`
	// RequiredParent optionally requires the immediate parent binary basename or path to match.
	RequiredParent string `json:"requiredParent,omitempty"`
	// ForbiddenAncestor optionally triggers when any ancestor in process lineage matches.
	ForbiddenAncestor string `json:"forbiddenAncestor,omitempty"`
	// Reason explains the security rationale recorded in audit events.
	Reason string `json:"reason,omitempty"`
}

// NetworkDirection identifies egress or bind socket operations.
type NetworkDirection string

const (
	NetDirAny    NetworkDirection = "any"
	NetDirEgress NetworkDirection = "egress"
	NetDirBind   NetworkDirection = "bind"
)

// NetworkRule defines an allow or deny rule over network egress or bind events.
type NetworkRule struct {
	// ID uniquely identifies the rule within the policy.
	ID string `json:"id"`
	// Priority determines deterministic evaluation order (higher runs first).
	Priority int `json:"priority"`
	// Effect is "allow" or "deny".
	Effect RuleEffect `json:"effect"`
	// Action optionally overrides the policy mode when Effect is "deny".
	Action EnforcementMode `json:"action,omitempty"`
	// Direction restricts matching to "egress", "bind", or "any" (default "any").
	Direction NetworkDirection `json:"direction,omitempty"`
	// Protocol restricts matching to "tcp", "udp", or "" / "any".
	Protocol string `json:"protocol,omitempty"`
	// CIDR specifies an IPv4 or IPv6 prefix (e.g., "169.254.169.254/32", "10.0.0.0/8", "0.0.0.0/0").
	CIDR string `json:"cidr"`
	// PortStart optionally restricts the destination/bind port lower bound (inclusive, 1..65535).
	PortStart uint16 `json:"portStart,omitempty"`
	// PortEnd optionally restricts the destination/bind port upper bound (inclusive, defaults to PortStart if PortStart > 0).
	PortEnd uint16 `json:"portEnd,omitempty"`
	// Reason explains the security rationale recorded in audit events.
	Reason string `json:"reason,omitempty"`
}

// TracingPolicy is a declarative, Tetragon-inspired runtime enforcement policy
// governing syscall, process execution, and network domains inside a Visor sandbox.
type TracingPolicy struct {
	// ID uniquely identifies the policy within a tenant.
	ID string `json:"id"`
	// Name is a human-readable policy name.
	Name string `json:"name"`
	// Version is a strictly positive monotonic policy version number.
	Version uint64 `json:"version"`
	// Mode sets the default enforcement mode ("audit_only", "enforce_deny", "enforce_sigkill").
	Mode EnforcementMode `json:"mode"`
	// Arch selects the target BPF architecture ("amd64" or "arm64"; defaults to "amd64").
	Arch string `json:"arch,omitempty"`
	// DefaultSyscallAllow determines the default verdict when no syscall rule matches (false = fail-closed).
	DefaultSyscallAllow bool `json:"defaultSyscallAllow"`
	// DefaultProcessAllow determines the default verdict when no process rule matches (false = fail-closed).
	DefaultProcessAllow bool `json:"defaultProcessAllow"`
	// DefaultNetworkAllow determines the default verdict when no network rule matches (false = fail-closed).
	DefaultNetworkAllow bool `json:"defaultNetworkAllow"`
	// DenyPrivEsc refuses UID/GID transitions, setuid executions, and unauthorized Linux capabilities.
	DenyPrivEsc bool `json:"denyPrivEsc"`
	// AuditAllowEvents controls whether benign ALLOW decisions are emitted to the audit ring.
	AuditAllowEvents bool `json:"auditAllowEvents,omitempty"`
	// SyscallRules lists declarative syscall rules.
	SyscallRules []SyscallRule `json:"syscallRules,omitempty"`
	// ProcessRules lists declarative process execution rules.
	ProcessRules []ProcessRule `json:"processRules,omitempty"`
	// NetworkRules lists declarative network egress/bind rules.
	NetworkRules []NetworkRule `json:"networkRules,omitempty"`
}

// CompiledPolicy is an immutable, pre-indexed runtime policy with generated
// seccomp-BPF filter bytecode ready for kernel attachment or VM evaluation.
type CompiledPolicy struct {
	Spec      TracingPolicy
	Digest    string
	BPF       BPFProgram
	BPFDigest string

	// O(1) syscall index keyed by Linux syscall number.
	syscallsByNum map[uint32][]compiledSyscallRule

	// Process indexes: O(1) exact canonical path map + root-segment bucketed prefix table + general rules.
	procExact        map[string][]compiledProcessRule
	procPrefixByRoot map[string][]compiledProcessRule
	procPrefix       []compiledProcessRule
	procGeneral      []compiledProcessRule

	// Network indexes: exact IP + bitmask-indexed CIDR tables for IPv4 (0..32) and IPv6 (0..128).
	netV4Mask   uint64
	netV4ByBit  [33]map[netip.Prefix][]compiledNetworkRule
	netV6MaskL  uint64 // bit lengths 0..63
	netV6MaskH  uint64 // bit lengths 64..127
	netV6Has128 bool
	netV6ByBit  [129]map[netip.Prefix][]compiledNetworkRule

	// Flat slices preserved for deterministic unindexed baseline comparisons.
	allSyscalls []compiledSyscallRule
	allProcs    []compiledProcessRule
	allNets     []compiledNetworkRule
}

type compiledSyscallRule struct {
	rule   SyscallRule
	num    uint32
	name   string
	action EnforcementMode
}

type compiledProcessRule struct {
	rule   ProcessRule
	exact  string
	prefix string
	argRe  *regexp.Regexp
	action EnforcementMode
}

type compiledNetworkRule struct {
	rule      NetworkRule
	prefix    netip.Prefix
	direction NetworkDirection
	protocol  string
	portStart uint16
	portEnd   uint16
	action    EnforcementMode
}

// NormalizeCanonicalPath validates and cleans an absolute POSIX path prior to
// prefix or exact matching. It rejects empty paths, NUL bytes, and relative paths.
func NormalizeCanonicalPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty path")
	}
	if strings.ContainsRune(raw, 0) {
		return "", errors.New("path contains NUL byte")
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("path %q must be absolute", raw)
	}
	cleaned := path.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("cleaned path %q is not absolute", cleaned)
	}
	return cleaned, nil
}

// PathMatchesPrefix reports whether canonicalPath equals prefix or resides
// strictly beneath prefix as a directory boundary (so "/usr/bin" matches
// "/usr/bin/go" and "/usr/bin", but NEVER "/usr/bin2/go").
func PathMatchesPrefix(canonicalPath, canonicalPrefix string) bool {
	if canonicalPrefix == "/" {
		return strings.HasPrefix(canonicalPath, "/")
	}
	if canonicalPath == canonicalPrefix {
		return true
	}
	return strings.HasPrefix(canonicalPath, canonicalPrefix+"/")
}

func pathRootSegment(canonicalPath string) string {
	if canonicalPath == "" || canonicalPath == "/" {
		return "/"
	}
	rest := strings.TrimPrefix(canonicalPath, "/")
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		return "/" + rest[:idx]
	}
	return "/" + rest
}

// NormalizeIP parses an IP string and unmaps IPv4-mapped IPv6 addresses
// (e.g., "::ffff:169.254.169.254" -> "169.254.169.254") so IPv4 CIDR denylists
// cannot be bypassed via IPv6 dual-stack notation.
func NormalizeIP(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP %q: %w", raw, err)
	}
	return addr.Unmap(), nil
}

// NormalizeCIDR parses and canonicalizes a CIDR prefix, unmapping IPv4-mapped
// IPv6 prefixes (e.g., "::ffff:169.254.169.254/128" -> "169.254.169.254/32").
func NormalizeCIDR(raw string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	addr := pfx.Addr()
	if addr.Is4In6() && pfx.Bits() >= 96 {
		unmapped := addr.Unmap()
		return netip.PrefixFrom(unmapped, pfx.Bits()-96).Masked(), nil
	}
	return pfx.Masked(), nil
}

func resolveEffectiveAction(policyMode, ruleAction EnforcementMode, effect RuleEffect) (EnforcementMode, error) {
	if effect == EffectAllow {
		return "", nil
	}
	// Under policy-wide AuditOnly, enforcement never escalates to blocking unless
	// explicitly running in an enforcement mode — matching Tetragon audit mode semantics.
	if policyMode == ModeAuditOnly {
		return ModeAuditOnly, nil
	}
	if ruleAction == "" {
		return policyMode, nil
	}
	parsed, err := ParseEnforcementMode(string(ruleAction))
	if err != nil {
		return "", err
	}
	// Under policy-wide EnforceDeny, cap rule action at EnforceDeny so an operator
	// choosing non-lethal EPERM mode is never unexpectedly killed by a Sigkill rule.
	if policyMode == ModeEnforceDeny && parsed == ModeEnforceSigkill {
		return ModeEnforceDeny, nil
	}
	return parsed, nil
}

// CompilePolicy validates, detects conflicts, indexes all three domains, and
// compiles kernel-ready seccomp-BPF filter bytecode. Any validation error or
// same-priority rule conflict fails closed with an error.
func CompilePolicy(spec TracingPolicy) (*CompiledPolicy, error) {
	spec.ID = strings.TrimSpace(spec.ID)
	spec.Name = strings.TrimSpace(spec.Name)
	if spec.ID == "" || len(spec.ID) > MaxFieldLen {
		return nil, fmt.Errorf("%w: policy id must be 1..%d chars", ErrInvalidPolicy, MaxFieldLen)
	}
	if spec.Name == "" {
		spec.Name = spec.ID
	}
	if len(spec.Name) > MaxFieldLen {
		return nil, fmt.Errorf("%w: policy name exceeds %d chars", ErrInvalidPolicy, MaxFieldLen)
	}
	if spec.Version == 0 {
		spec.Version = 1
	}
	mode, err := ParseEnforcementMode(string(spec.Mode))
	if err != nil {
		return nil, err
	}
	spec.Mode = mode
	if spec.Arch == "" {
		spec.Arch = "amd64"
	}
	if spec.Arch != "amd64" && spec.Arch != "arm64" {
		return nil, fmt.Errorf("%w: unsupported arch %q (want amd64 or arm64)", ErrInvalidPolicy, spec.Arch)
	}

	totalRules := len(spec.SyscallRules) + len(spec.ProcessRules) + len(spec.NetworkRules)
	if totalRules > MaxPolicyRules {
		return nil, fmt.Errorf("%w: %d rules exceeds max %d", ErrRuleLimitExceeded, totalRules, MaxPolicyRules)
	}

	cp := &CompiledPolicy{
		Spec:             spec,
		syscallsByNum:    make(map[uint32][]compiledSyscallRule, len(spec.SyscallRules)),
		procExact:        make(map[string][]compiledProcessRule),
		procPrefixByRoot: make(map[string][]compiledProcessRule),
	}

	seenRuleIDs := make(map[string]struct{}, totalRules)
	checkID := func(id string) error {
		id = strings.TrimSpace(id)
		if id == "" || len(id) > MaxFieldLen {
			return fmt.Errorf("%w: rule id must be 1..%d chars", ErrInvalidPolicy, MaxFieldLen)
		}
		if _, dup := seenRuleIDs[id]; dup {
			return fmt.Errorf("%w: duplicate rule id %q", ErrInvalidPolicy, id)
		}
		seenRuleIDs[id] = struct{}{}
		return nil
	}

	// 1. Compile and conflict-check Syscall rules.
	type sysConflictKey struct {
		num      uint32
		priority int
		argsKey  string
	}
	sysConflicts := make(map[sysConflictKey]RuleEffect, len(spec.SyscallRules))

	for i, r := range spec.SyscallRules {
		r.ID = strings.TrimSpace(r.ID)
		if err := checkID(r.ID); err != nil {
			return nil, fmt.Errorf("syscall rule[%d]: %w", i, err)
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return nil, fmt.Errorf("%w: syscall rule %q invalid effect %q", ErrInvalidPolicy, r.ID, r.Effect)
		}
		if len(r.ArgFilters) > MaxArgFiltersPerRule {
			return nil, fmt.Errorf("%w: syscall rule %q has %d arg filters (max %d)", ErrInvalidPolicy, r.ID, len(r.ArgFilters), MaxArgFiltersPerRule)
		}
		num, name, err := resolveSyscallIdentity(r.SyscallName, r.SyscallNumber)
		if err != nil {
			return nil, fmt.Errorf("syscall rule %q: %w", r.ID, err)
		}
		var argsKeyB strings.Builder
		for _, af := range r.ArgFilters {
			if af.Index > 5 {
				return nil, fmt.Errorf("%w: syscall rule %q arg index %d out of range [0..5]", ErrInvalidPolicy, r.ID, af.Index)
			}
			switch af.Op {
			case ArgOpEqual, ArgOpNotEqual, ArgOpMaskAny, ArgOpMaskAll, ArgOpGreaterEq, ArgOpLessEq:
			default:
				return nil, fmt.Errorf("%w: syscall rule %q unsupported arg op %q", ErrInvalidPolicy, r.ID, af.Op)
			}
			fmt.Fprintf(&argsKeyB, "%d:%s:%d;", af.Index, af.Op, af.Value)
		}
		ck := sysConflictKey{num: num, priority: r.Priority, argsKey: argsKeyB.String()}
		if prevEff, exists := sysConflicts[ck]; exists && prevEff != r.Effect {
			return nil, fmt.Errorf("%w: syscall %s (%d) priority %d", ErrPolicyConflict, name, num, r.Priority)
		}
		sysConflicts[ck] = r.Effect

		act, err := resolveEffectiveAction(spec.Mode, r.Action, r.Effect)
		if err != nil {
			return nil, fmt.Errorf("syscall rule %q: %w", r.ID, err)
		}
		cr := compiledSyscallRule{rule: r, num: num, name: name, action: act}
		cp.syscallsByNum[num] = append(cp.syscallsByNum[num], cr)
		cp.allSyscalls = append(cp.allSyscalls, cr)
	}
	for num := range cp.syscallsByNum {
		sortSyscallRules(cp.syscallsByNum[num])
	}
	sortSyscallRules(cp.allSyscalls)

	// 2. Compile and conflict-check Process rules.
	type procConflictKey struct {
		exact    string
		prefix   string
		argSub   string
		argRe    string
		parent   string
		ancestor string
		priority int
	}
	procConflicts := make(map[procConflictKey]RuleEffect, len(spec.ProcessRules))

	for i, r := range spec.ProcessRules {
		r.ID = strings.TrimSpace(r.ID)
		if err := checkID(r.ID); err != nil {
			return nil, fmt.Errorf("process rule[%d]: %w", i, err)
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return nil, fmt.Errorf("%w: process rule %q invalid effect %q", ErrInvalidPolicy, r.ID, r.Effect)
		}
		var exact, pfx string
		if r.BinaryExact != "" {
			exact, err = NormalizeCanonicalPath(r.BinaryExact)
			if err != nil {
				return nil, fmt.Errorf("%w: process rule %q binaryExact: %v", ErrInvalidPolicy, r.ID, err)
			}
		}
		if r.BinaryPrefix != "" {
			pfx, err = NormalizeCanonicalPath(r.BinaryPrefix)
			if err != nil {
				return nil, fmt.Errorf("%w: process rule %q binaryPrefix: %v", ErrInvalidPolicy, r.ID, err)
			}
		}
		if exact == "" && pfx == "" && r.ArgContains == "" && r.ArgRegex == "" && r.RequiredParent == "" && r.ForbiddenAncestor == "" {
			return nil, fmt.Errorf("%w: process rule %q has no match criteria", ErrInvalidPolicy, r.ID)
		}
		var re *regexp.Regexp
		if r.ArgRegex != "" {
			if len(r.ArgRegex) > MaxFieldLen {
				return nil, fmt.Errorf("%w: process rule %q argRegex too long", ErrInvalidPolicy, r.ID)
			}
			re, err = regexp.Compile(r.ArgRegex)
			if err != nil {
				return nil, fmt.Errorf("%w: process rule %q invalid argRegex: %v", ErrInvalidPolicy, r.ID, err)
			}
		}
		ck := procConflictKey{
			exact: exact, prefix: pfx, argSub: r.ArgContains, argRe: r.ArgRegex,
			parent: r.RequiredParent, ancestor: r.ForbiddenAncestor, priority: r.Priority,
		}
		if prevEff, exists := procConflicts[ck]; exists && prevEff != r.Effect {
			return nil, fmt.Errorf("%w: process rule %q at priority %d", ErrPolicyConflict, r.ID, r.Priority)
		}
		procConflicts[ck] = r.Effect

		act, err := resolveEffectiveAction(spec.Mode, r.Action, r.Effect)
		if err != nil {
			return nil, fmt.Errorf("process rule %q: %w", r.ID, err)
		}
		cr := compiledProcessRule{
			rule:   r,
			exact:  exact,
			prefix: pfx,
			argRe:  re,
			action: act,
		}
		cp.allProcs = append(cp.allProcs, cr)
		if exact != "" {
			cp.procExact[exact] = append(cp.procExact[exact], cr)
		} else if pfx != "" {
			cp.procPrefix = append(cp.procPrefix, cr)
			root := pathRootSegment(pfx)
			cp.procPrefixByRoot[root] = append(cp.procPrefixByRoot[root], cr)
		} else {
			cp.procGeneral = append(cp.procGeneral, cr)
		}
	}
	for k := range cp.procExact {
		sortProcessRules(cp.procExact[k])
	}
	for k := range cp.procPrefixByRoot {
		sortProcessRules(cp.procPrefixByRoot[k])
	}
	sortProcessRules(cp.procPrefix)
	sortProcessRules(cp.procGeneral)
	sortProcessRules(cp.allProcs)

	// 3. Compile and conflict-check Network rules.
	type netConflictKey struct {
		cidr      string
		direction NetworkDirection
		protocol  string
		portStart uint16
		portEnd   uint16
		priority  int
	}
	netConflicts := make(map[netConflictKey]RuleEffect, len(spec.NetworkRules))

	for i, r := range spec.NetworkRules {
		r.ID = strings.TrimSpace(r.ID)
		if err := checkID(r.ID); err != nil {
			return nil, fmt.Errorf("network rule[%d]: %w", i, err)
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return nil, fmt.Errorf("%w: network rule %q invalid effect %q", ErrInvalidPolicy, r.ID, r.Effect)
		}
		pfx, err := NormalizeCIDR(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("%w: network rule %q: %v", ErrInvalidPolicy, r.ID, err)
		}
		dir := r.Direction
		if dir == "" {
			dir = NetDirAny
		}
		if dir != NetDirAny && dir != NetDirEgress && dir != NetDirBind {
			return nil, fmt.Errorf("%w: network rule %q invalid direction %q", ErrInvalidPolicy, r.ID, dir)
		}
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto == "any" {
			proto = ""
		}
		if proto != "" && proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("%w: network rule %q invalid protocol %q", ErrInvalidPolicy, r.ID, proto)
		}
		pStart, pEnd := r.PortStart, r.PortEnd
		if pStart > 0 && pEnd == 0 {
			pEnd = pStart
		}
		if pEnd > 0 && pStart == 0 {
			pStart = pEnd
		}
		if pEnd < pStart {
			return nil, fmt.Errorf("%w: network rule %q portEnd %d < portStart %d", ErrInvalidPolicy, r.ID, pEnd, pStart)
		}
		ck := netConflictKey{
			cidr: pfx.String(), direction: dir, protocol: proto,
			portStart: pStart, portEnd: pEnd, priority: r.Priority,
		}
		if prevEff, exists := netConflicts[ck]; exists && prevEff != r.Effect {
			return nil, fmt.Errorf("%w: network CIDR %s priority %d", ErrPolicyConflict, pfx.String(), r.Priority)
		}
		netConflicts[ck] = r.Effect

		act, err := resolveEffectiveAction(spec.Mode, r.Action, r.Effect)
		if err != nil {
			return nil, fmt.Errorf("network rule %q: %w", r.ID, err)
		}
		cr := compiledNetworkRule{
			rule:      r,
			prefix:    pfx,
			direction: dir,
			protocol:  proto,
			portStart: pStart,
			portEnd:   pEnd,
			action:    act,
		}
		cp.allNets = append(cp.allNets, cr)
		bits := pfx.Bits()
		if pfx.Addr().Is4() {
			if cp.netV4ByBit[bits] == nil {
				cp.netV4ByBit[bits] = make(map[netip.Prefix][]compiledNetworkRule)
			}
			cp.netV4ByBit[bits][pfx] = append(cp.netV4ByBit[bits][pfx], cr)
			cp.netV4Mask |= uint64(1) << uint(bits)
		} else {
			if cp.netV6ByBit[bits] == nil {
				cp.netV6ByBit[bits] = make(map[netip.Prefix][]compiledNetworkRule)
			}
			cp.netV6ByBit[bits][pfx] = append(cp.netV6ByBit[bits][pfx], cr)
			switch {
			case bits < 64:
				cp.netV6MaskL |= uint64(1) << uint(bits)
			case bits < 128:
				cp.netV6MaskH |= uint64(1) << uint(bits-64)
			default:
				cp.netV6Has128 = true
			}
		}
	}
	for b := range cp.netV4ByBit {
		for k := range cp.netV4ByBit[b] {
			sortNetworkRules(cp.netV4ByBit[b][k])
		}
	}
	for b := range cp.netV6ByBit {
		for k := range cp.netV6ByBit[b] {
			sortNetworkRules(cp.netV6ByBit[b][k])
		}
	}
	sortNetworkRules(cp.allNets)

	// 4. Compile real kernel-ready classic seccomp-BPF filter program.
	bpfProg, err := CompileSeccompBPF(cp)
	if err != nil {
		return nil, fmt.Errorf("compile seccomp-bpf: %w", err)
	}
	cp.BPF = bpfProg
	cp.BPFDigest = bpfProg.Digest()
	cp.Digest = computePolicyDigest(cp)
	return cp, nil
}

func sortSyscallRules(rules []compiledSyscallRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].rule.Priority != rules[j].rule.Priority {
			return rules[i].rule.Priority > rules[j].rule.Priority
		}
		si, sj := modeSeverity(rules[i].action), modeSeverity(rules[j].action)
		if si != sj {
			return si > sj
		}
		return rules[i].rule.ID < rules[j].rule.ID
	})
}

func sortProcessRules(rules []compiledProcessRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].rule.Priority != rules[j].rule.Priority {
			return rules[i].rule.Priority > rules[j].rule.Priority
		}
		si, sj := modeSeverity(rules[i].action), modeSeverity(rules[j].action)
		if si != sj {
			return si > sj
		}
		return rules[i].rule.ID < rules[j].rule.ID
	})
}

func sortNetworkRules(rules []compiledNetworkRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].rule.Priority != rules[j].rule.Priority {
			return rules[i].rule.Priority > rules[j].rule.Priority
		}
		si, sj := modeSeverity(rules[i].action), modeSeverity(rules[j].action)
		if si != sj {
			return si > sj
		}
		return rules[i].rule.ID < rules[j].rule.ID
	})
}

func computePolicyDigest(cp *CompiledPolicy) string {
	h := sha256.New()
	h.Write([]byte("hanzo-sandboxpolicy-v1\x00"))
	writeStr := func(s string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(s)))
		h.Write(b[:])
		h.Write([]byte(s))
	}
	writeU64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		h.Write(b[:])
	}
	writeStr(cp.Spec.ID)
	writeStr(cp.Spec.Name)
	writeU64(cp.Spec.Version)
	writeStr(string(cp.Spec.Mode))
	writeStr(cp.Spec.Arch)
	writeStr(cp.BPFDigest)
	for _, r := range cp.allSyscalls {
		writeStr(r.rule.ID)
		writeU64(uint64(r.num))
		writeStr(string(r.rule.Effect))
		writeStr(string(r.action))
	}
	for _, r := range cp.allProcs {
		writeStr(r.rule.ID)
		writeStr(r.exact)
		writeStr(r.prefix)
		writeStr(string(r.rule.Effect))
		writeStr(string(r.action))
	}
	for _, r := range cp.allNets {
		writeStr(r.rule.ID)
		writeStr(r.prefix.String())
		writeStr(string(r.rule.Effect))
		writeStr(string(r.action))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Canonical Linux x86_64 syscall table for clean-room resolution and seccomp-BPF emission.
var syscallNameToNum = map[string]uint32{
	"read":              0,
	"write":             1,
	"open":              2,
	"close":             3,
	"stat":              4,
	"fstat":             5,
	"lstat":             6,
	"poll":              7,
	"lseek":             8,
	"mmap":              9,
	"mprotect":          10,
	"munmap":            11,
	"brk":               12,
	"rt_sigaction":      13,
	"rt_sigprocmask":    14,
	"rt_sigreturn":      15,
	"ioctl":             16,
	"pread64":           17,
	"pwrite64":          18,
	"readv":             19,
	"writev":            20,
	"access":            21,
	"pipe":              22,
	"select":            23,
	"sched_yield":       24,
	"mremap":            25,
	"madvise":           28,
	"dup":               32,
	"dup2":              33,
	"nanosleep":         35,
	"getpid":            39,
	"socket":            41,
	"connect":           42,
	"accept":            43,
	"sendto":            44,
	"recvfrom":          45,
	"sendmsg":           46,
	"recvmsg":           47,
	"shutdown":          48,
	"bind":              49,
	"listen":            50,
	"getsockname":       51,
	"getpeername":       52,
	"socketpair":        53,
	"setsockopt":        54,
	"getsockopt":        55,
	"clone":             56,
	"fork":              57,
	"vfork":             58,
	"execve":            59,
	"exit":              60,
	"wait4":             61,
	"kill":              62,
	"uname":             63,
	"fcntl":             72,
	"flock":             73,
	"fsync":             74,
	"fdatasync":         75,
	"truncate":          76,
	"ftruncate":         77,
	"getcwd":            79,
	"chdir":             80,
	"fchdir":            81,
	"rename":            82,
	"mkdir":             83,
	"rmdir":             84,
	"link":              86,
	"unlink":            87,
	"symlink":           88,
	"readlink":          89,
	"chmod":             90,
	"fchmod":            91,
	"umask":             95,
	"gettimeofday":      96,
	"getrlimit":         97,
	"getrusage":         98,
	"sysinfo":           99,
	"times":             100,
	"ptrace":            101,
	"getuid":            102,
	"getgid":            104,
	"setuid":            105,
	"setgid":            106,
	"geteuid":           107,
	"getegid":           108,
	"getppid":           110,
	"sigaltstack":       131,
	"statfs":            137,
	"fstatfs":           138,
	"pivot_root":        155,
	"prctl":             157,
	"arch_prctl":        158,
	"chroot":            161,
	"mount":             165,
	"umount2":           166,
	"init_module":       175,
	"delete_module":     176,
	"gettid":            186,
	"futex":             202,
	"getdents64":        217,
	"set_tid_address":   218,
	"clock_gettime":     228,
	"clock_nanosleep":   230,
	"exit_group":        231,
	"epoll_ctl":         233,
	"tgkill":            234,
	"kexec_load":        246,
	"waitid":            247,
	"add_key":           248,
	"keyctl":            250,
	"openat":            257,
	"mkdirat":           258,
	"newfstatat":        262,
	"unlinkat":          263,
	"renameat":          264,
	"linkat":            265,
	"symlinkat":         266,
	"readlinkat":        267,
	"fchmodat":          268,
	"faccessat":         269,
	"unshare":           272,
	"set_robust_list":   273,
	"epoll_pwait":       281,
	"accept4":           288,
	"eventfd2":          290,
	"epoll_create1":     291,
	"dup3":              292,
	"pipe2":             293,
	"perf_event_open":   298,
	"prlimit64":         302,
	"open_by_handle_at": 304,
	"setns":             308,
	"process_vm_readv":  310,
	"process_vm_writev": 311,
	"finit_module":      313,
	"renameat2":         316,
	"getrandom":         318,
	"memfd_create":      319,
	"kexec_file_load":   320,
	"bpf":               321,
	"userfaultfd":       323,
	"statx":             332,
	"io_uring_setup":    425,
	"clone3":            435,
}

var syscallNumToName = func() map[uint32]string {
	m := make(map[uint32]string, len(syscallNameToNum))
	for name, num := range syscallNameToNum {
		m[num] = name
	}
	return m
}()

// LookupSyscallNumber resolves a canonical Linux x86_64 syscall name to its number.
func LookupSyscallNumber(name string) (uint32, bool) {
	num, ok := syscallNameToNum[strings.ToLower(strings.TrimSpace(name))]
	return num, ok
}

// LookupSyscallName resolves a Linux x86_64 syscall number to its canonical name.
func LookupSyscallName(num uint32) string {
	if name, ok := syscallNumToName[num]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", num)
}

func resolveSyscallIdentity(name string, numPtr *int) (uint32, string, error) {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	if numPtr != nil {
		if *numPtr < 0 || *numPtr > MaxSyscallNumber {
			return 0, "", fmt.Errorf("%w: syscall number %d out of range [0..%d]", ErrInvalidPolicy, *numPtr, MaxSyscallNumber)
		}
		num := uint32(*numPtr)
		if cleanName != "" {
			if expected, ok := syscallNameToNum[cleanName]; ok && expected != num {
				return 0, "", fmt.Errorf("%w: syscall %q maps to %d, not %d", ErrInvalidPolicy, cleanName, expected, num)
			}
			return num, cleanName, nil
		}
		return num, LookupSyscallName(num), nil
	}
	if cleanName == "" {
		return 0, "", fmt.Errorf("%w: syscall rule requires syscallName or syscallNumber", ErrInvalidPolicy)
	}
	num, ok := syscallNameToNum[cleanName]
	if !ok {
		return 0, "", fmt.Errorf("%w: unknown syscall name %q", ErrInvalidPolicy, cleanName)
	}
	return num, cleanName, nil
}

// Linux namespace/socket constants used by DefaultVisorSandboxPolicy.
const (
	CloneNewNS   uint64 = 0x00020000
	CloneNewUser uint64 = 0x10000000
	CloneNewPID  uint64 = 0x20000000
	CloneNewNet  uint64 = 0x40000000

	AFNetlink uint64 = 16
	AFPacket  uint64 = 17
)

// DefaultVisorSandboxPolicy returns a hardened, fail-closed Tetragon-inspired
// TracingPolicy tailored for Visor coding-agent sandboxes (Go, Git, Node/npm,
// shell utilities) while blocking container escapes, kernel attacks, privilege
// escalations, metadata-endpoint SSRF, and lateral private-network access.
func DefaultVisorSandboxPolicy(mode EnforcementMode) TracingPolicy {
	if mode == "" {
		mode = ModeEnforceSigkill
	}

	benignSyscalls := []string{
		"read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
		"newfstatat", "statx", "poll", "lseek", "mmap", "mprotect", "munmap",
		"brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
		"pread64", "pwrite64", "readv", "writev", "access", "faccessat",
		"pipe", "pipe2", "select", "sched_yield", "mremap", "madvise",
		"dup", "dup2", "dup3", "nanosleep", "clock_gettime", "clock_nanosleep",
		"getpid", "gettid", "getppid", "getuid", "geteuid", "getgid", "getegid",
		"socket", "connect", "accept", "accept4", "sendto", "recvfrom",
		"sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname",
		"getpeername", "socketpair", "setsockopt", "getsockopt",
		"clone", "clone3", "fork", "vfork", "execve", "exit", "exit_group",
		"wait4", "waitid", "kill", "tgkill", "uname", "fcntl", "flock",
		"fsync", "fdatasync", "truncate", "ftruncate", "getdents64",
		"getcwd", "chdir", "fchdir", "rename", "renameat", "renameat2",
		"mkdir", "mkdirat", "rmdir", "link", "linkat", "unlink", "unlinkat",
		"symlink", "symlinkat", "readlink", "readlinkat", "chmod", "fchmod",
		"fchmodat", "umask", "gettimeofday", "getrlimit", "prlimit64",
		"getrusage", "sysinfo", "times", "sigaltstack", "statfs", "fstatfs",
		"prctl", "arch_prctl", "futex", "set_tid_address", "set_robust_list",
		"epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "getrandom",
	}

	sysRules := []SyscallRule{
		// High-priority container-escape & kernel-surface denylist.
		{ID: "sys-deny-ptrace", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "ptrace", Reason: "prevent process memory inspection and sandbox breakout"},
		{ID: "sys-deny-mount", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "mount", Reason: "prevent filesystem mount escapes"},
		{ID: "sys-deny-umount2", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "umount2", Reason: "prevent filesystem unmount manipulation"},
		{ID: "sys-deny-pivot-root", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "pivot_root", Reason: "prevent rootfs pivot escape"},
		{ID: "sys-deny-chroot", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "chroot", Reason: "prevent chroot escape primitives"},
		{ID: "sys-deny-init-module", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "init_module", Reason: "prevent kernel module loading"},
		{ID: "sys-deny-finit-module", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "finit_module", Reason: "prevent fd kernel module loading"},
		{ID: "sys-deny-delete-module", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "delete_module", Reason: "prevent kernel module unloading"},
		{ID: "sys-deny-bpf", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "bpf", Reason: "prevent unprivileged eBPF program loading from sandbox"},
		{ID: "sys-deny-setns", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "setns", Reason: "prevent joining host namespaces"},
		{ID: "sys-deny-unshare", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "unshare", Reason: "prevent namespace creation for privilege escalation"},
		{ID: "sys-deny-open-by-handle-at", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "open_by_handle_at", Reason: "prevent Shocker file-handle container escape"},
		{ID: "sys-deny-kexec-load", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "kexec_load", Reason: "prevent kernel replacement"},
		{ID: "sys-deny-kexec-file-load", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "kexec_file_load", Reason: "prevent kernel replacement"},
		{ID: "sys-deny-process-vm-readv", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "process_vm_readv", Reason: "prevent cross-process memory reads"},
		{ID: "sys-deny-process-vm-writev", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "process_vm_writev", Reason: "prevent cross-process memory writes"},
		{ID: "sys-deny-userfaultfd", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, SyscallName: "userfaultfd", Reason: "reduce kernel exploit primitive surface"},
		{ID: "sys-deny-perf-event-open", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, SyscallName: "perf_event_open", Reason: "prevent side-channel and kernel perf attacks"},
		{ID: "sys-deny-io-uring-setup", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, SyscallName: "io_uring_setup", Reason: "prevent io_uring kernel bypass surface"},
		{ID: "sys-deny-memfd-create", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, SyscallName: "memfd_create", Reason: "prevent fileless in-memory ELF execution"},
		{ID: "sys-deny-keyctl", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, SyscallName: "keyctl", Reason: "prevent kernel keyring tampering"},
		{ID: "sys-deny-setuid", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "setuid", Reason: "prevent UID privilege escalation"},
		{ID: "sys-deny-setgid", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, SyscallName: "setgid", Reason: "prevent GID privilege escalation"},
		// Argument-filtered syscall rules (e.g., clone with namespace flags, raw/netlink sockets).
		{
			ID: "sys-deny-clone-ns", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill,
			SyscallName: "clone",
			ArgFilters:  []SyscallArgFilter{{Index: 0, Op: ArgOpMaskAny, Value: CloneNewUser | CloneNewNS | CloneNewPID | CloneNewNet}},
			Reason:      "prevent user/mount/pid/net namespace creation via clone",
		},
		{
			ID: "sys-deny-socket-packet", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny,
			SyscallName: "socket",
			ArgFilters:  []SyscallArgFilter{{Index: 0, Op: ArgOpEqual, Value: AFPacket}},
			Reason:      "prevent AF_PACKET raw packet capture",
		},
		{
			ID: "sys-deny-socket-netlink", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny,
			SyscallName: "socket",
			ArgFilters:  []SyscallArgFilter{{Index: 0, Op: ArgOpEqual, Value: AFNetlink}},
			Reason:      "prevent AF_NETLINK kernel netlink socket manipulation",
		},
	}

	for _, name := range benignSyscalls {
		sysRules = append(sysRules, SyscallRule{
			ID:          "sys-allow-" + name,
			Priority:    100,
			Effect:      EffectAllow,
			SyscallName: name,
			Reason:      "benign sandbox syscall allowlisted in-kernel",
		})
	}

	procRules := []ProcessRule{
		// Explicit high-priority blocked binaries and escape tools.
		{ID: "proc-deny-sudo", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/sudo", Reason: "privilege escalation binary forbidden"},
		{ID: "proc-deny-su", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/su", Reason: "privilege escalation binary forbidden"},
		{ID: "proc-deny-bin-su", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/bin/su", Reason: "privilege escalation binary forbidden"},
		{ID: "proc-deny-nsenter", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/nsenter", Reason: "namespace breakout binary forbidden"},
		{ID: "proc-deny-unshare", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/unshare", Reason: "namespace creation binary forbidden"},
		{ID: "proc-deny-mount", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/mount", Reason: "mount binary forbidden"},
		{ID: "proc-deny-bin-mount", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/bin/mount", Reason: "mount binary forbidden"},
		{ID: "proc-deny-chroot", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/sbin/chroot", Reason: "chroot binary forbidden"},
		{ID: "proc-deny-docker", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/docker", Reason: "container runtime control binary forbidden"},
		{ID: "proc-deny-kubectl", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/kubectl", Reason: "cluster control binary forbidden"},
		{ID: "proc-deny-gdb", Priority: 950, Effect: EffectDeny, Action: ModeEnforceDeny, BinaryExact: "/usr/bin/gdb", Reason: "debugger binary forbidden in sandbox"},
		{ID: "proc-deny-strace", Priority: 950, Effect: EffectDeny, Action: ModeEnforceDeny, BinaryExact: "/usr/bin/strace", Reason: "tracer binary forbidden in sandbox"},
		{ID: "proc-deny-sbin", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryPrefix: "/sbin", Reason: "system admin binaries forbidden"},
		{ID: "proc-deny-usr-sbin", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryPrefix: "/usr/sbin", Reason: "system admin binaries forbidden"},

		// Argument pattern rules blocking reverse shells, host proc escapes, and IMDS fetches.
		{ID: "proc-deny-arg-proc-root", Priority: 900, Effect: EffectDeny, Action: ModeEnforceSigkill, ArgContains: "/proc/1/root", Reason: "block host filesystem traversal via /proc/1/root"},
		{ID: "proc-deny-arg-docker-sock", Priority: 900, Effect: EffectDeny, Action: ModeEnforceSigkill, ArgContains: "docker.sock", Reason: "block Docker socket escape"},
		{ID: "proc-deny-arg-dev-tcp", Priority: 900, Effect: EffectDeny, Action: ModeEnforceSigkill, ArgContains: "/dev/tcp/", Reason: "block bash /dev/tcp reverse shell"},
		{ID: "proc-deny-arg-imds", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, ArgContains: "169.254.169.254", Reason: "block cloud metadata SSRF via CLI"},

		// Lineage restriction: disallow curl/wget spawned directly by untrusted python/node eval chains if desired,
		// and forbid any descendant of an already-flagged untrusted helper.
		{ID: "proc-deny-lineage-nc", Priority: 900, Effect: EffectDeny, Action: ModeEnforceSigkill, BinaryExact: "/usr/bin/nc", Reason: "netcat binary forbidden"},

		// Allowlisted Visor agent toolchain prefixes.
		{ID: "proc-allow-go", Priority: 100, Effect: EffectAllow, BinaryPrefix: "/usr/local/go/bin", Reason: "Go toolchain allowlisted"},
		{ID: "proc-allow-usr-bin", Priority: 100, Effect: EffectAllow, BinaryPrefix: "/usr/bin", Reason: "standard userland utilities allowlisted"},
		{ID: "proc-allow-bin", Priority: 100, Effect: EffectAllow, BinaryPrefix: "/bin", Reason: "core POSIX utilities allowlisted"},
		{ID: "proc-allow-usr-local-bin", Priority: 100, Effect: EffectAllow, BinaryPrefix: "/usr/local/bin", Reason: "local developer tools allowlisted"},
		{ID: "proc-allow-workspace-bin", Priority: 100, Effect: EffectAllow, BinaryPrefix: "/workspace/.bin", Reason: "workspace build outputs allowlisted"},
		{ID: "proc-allow-tmp-go-build", Priority: 100, Effect: EffectAllow, BinaryPrefix: "/tmp/go-build", Reason: "go test compiled test binaries allowlisted"},
	}

	netRules := []NetworkRule{
		// Highest priority: Cloud IMDS & Link-Local metadata endpoints.
		{ID: "net-deny-imds-v4", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, Direction: NetDirAny, CIDR: "169.254.169.254/32", Reason: "block AWS/GCP/Azure IMDSv1/v2 metadata endpoint"},
		{ID: "net-deny-link-local-v4", Priority: 990, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirAny, CIDR: "169.254.0.0/16", Reason: "block IPv4 link-local range"},
		{ID: "net-deny-imds-v6", Priority: 1000, Effect: EffectDeny, Action: ModeEnforceSigkill, Direction: NetDirAny, CIDR: "fd00:ec2::254/128", Reason: "block AWS IPv6 metadata endpoint"},
		{ID: "net-deny-link-local-v6", Priority: 990, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirAny, CIDR: "fe80::/10", Reason: "block IPv6 link-local range"},

		// High priority: Private / cluster / control-plane networks (prevent lateral movement).
		{ID: "net-deny-rfc1918-10", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirEgress, CIDR: "10.0.0.0/8", Reason: "block RFC1918 10/8 internal cluster egress"},
		{ID: "net-deny-rfc1918-172", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirEgress, CIDR: "172.16.0.0/12", Reason: "block RFC1918 172.16/12 internal cluster egress"},
		{ID: "net-deny-rfc1918-192", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirEgress, CIDR: "192.168.0.0/16", Reason: "block RFC1918 192.168/16 internal network egress"},
		{ID: "net-deny-cgnat", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirEgress, CIDR: "100.64.0.0/10", Reason: "block CGNAT/mesh internal egress"},
		{ID: "net-deny-ula-v6", Priority: 900, Effect: EffectDeny, Action: ModeEnforceDeny, Direction: NetDirEgress, CIDR: "fc00::/7", Reason: "block IPv6 ULA private egress"},

		// Loopback daemon ports denied (Docker 2375/2376, etcd 2379, kubelet 10250, K8s 6443).
		{ID: "net-deny-loopback-docker", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, Direction: NetDirEgress, CIDR: "127.0.0.0/8", PortStart: 2375, PortEnd: 2379, Reason: "block loopback Docker/etcd daemon access"},
		{ID: "net-deny-loopback-kube", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, Direction: NetDirEgress, CIDR: "127.0.0.0/8", PortStart: 6443, PortEnd: 6443, Reason: "block loopback Kubernetes API access"},
		{ID: "net-deny-loopback-v6-docker", Priority: 950, Effect: EffectDeny, Action: ModeEnforceSigkill, Direction: NetDirEgress, CIDR: "::1/128", PortStart: 2375, PortEnd: 2379, Reason: "block IPv6 loopback Docker/etcd daemon access"},
		// Allow ephemeral local dev/test loopback binds & connections (e.g., httptest in go test).
		{ID: "net-allow-loopback-ephemeral-v4", Priority: 200, Effect: EffectAllow, Direction: NetDirAny, Protocol: "tcp", CIDR: "127.0.0.0/8", PortStart: 32768, PortEnd: 65535, Reason: "allow ephemeral loopback ports for local unit tests"},
		{ID: "net-allow-loopback-ephemeral-v6", Priority: 200, Effect: EffectAllow, Direction: NetDirAny, Protocol: "tcp", CIDR: "::1/128", PortStart: 32768, PortEnd: 65535, Reason: "allow ephemeral IPv6 loopback ports for local unit tests"},

		// Allowlisted public API HTTPS (443) and DNS (53) egress.
		{ID: "net-allow-https-v4", Priority: 100, Effect: EffectAllow, Direction: NetDirEgress, Protocol: "tcp", CIDR: "0.0.0.0/0", PortStart: 443, PortEnd: 443, Reason: "allow HTTPS egress to public APIs and package registries"},
		{ID: "net-allow-https-v6", Priority: 100, Effect: EffectAllow, Direction: NetDirEgress, Protocol: "tcp", CIDR: "::/0", PortStart: 443, PortEnd: 443, Reason: "allow IPv6 HTTPS egress"},
		{ID: "net-allow-dns-udp-v4", Priority: 100, Effect: EffectAllow, Direction: NetDirEgress, Protocol: "udp", CIDR: "0.0.0.0/0", PortStart: 53, PortEnd: 53, Reason: "allow UDP DNS resolution"},
		{ID: "net-allow-dns-tcp-v4", Priority: 100, Effect: EffectAllow, Direction: NetDirEgress, Protocol: "tcp", CIDR: "0.0.0.0/0", PortStart: 53, PortEnd: 53, Reason: "allow TCP DNS resolution"},
	}

	return TracingPolicy{
		ID:                  "visor-sandbox-default",
		Name:                "Visor Agent Sandbox Default Policy (HIP-1349)",
		Version:             1,
		Mode:                mode,
		Arch:                "amd64",
		DefaultSyscallAllow: false,
		DefaultProcessAllow: false,
		DefaultNetworkAllow: false,
		DenyPrivEsc:         true,
		AuditAllowEvents:    false,
		SyscallRules:        sysRules,
		ProcessRules:        procRules,
		NetworkRules:        netRules,
	}
}
