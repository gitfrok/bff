// Package plane resolves which plane this BFF is deployed on, and refuses configurations that
// contradict it.
//
// ADR-0094 decision 5: "bff and webfrontend remain one codebase each, deployed twice with different
// route sets enabled. A control-plane deployment refuses to start with a RepositoryReader address
// configured; a data-plane deployment requires one. The refusal is the enforcement: a misconfigured
// deployment fails at boot rather than serving a route it should not have."
//
// The refusal being the enforcement is why this package exists as its own unit rather than a few
// ifs in main: the two refusals are the security property, so they are the thing under test.
//
// ADR-0100 decision 6 adds the other half. A control-plane deployment configures the control-plane
// door and NO data-plane address at all, which makes ADR-0011's no-dial rule structural rather than
// asserted — there is no address to dial. A data-plane deployment is the mirror.
package plane

import (
	"errors"
	"fmt"
	"strings"
)

// Plane is which side of ADR-0009's split this process serves.
type Plane string

const (
	// Control serves ADR-0094 decision 4's metadata surfaces and renders no repository content.
	Control Plane = "control"
	// Data serves ADR-0094 decision 3's repository surface and reads git-storaged in-cluster.
	Data Plane = "data"
)

// Environment variable names. The rename of PDPAddr is ADR-0100 decision 5: the old name asserted
// one service while carrying fourteen, which is how SPEC-0070 mis-sized its own problem for an
// afternoon. Both are accepted for one release.
const (
	PlaneEnv = "GITFROK_PLANE"

	DataplaneAddrEnv = "GITFROK_DATAPLANE_ADDR"
	// LegacyDataplaneAddrEnv is accepted for one release (ADR-0100 decision 5, additively).
	LegacyDataplaneAddrEnv = "GITFROK_PDP_ADDR"

	ControlplaneAddrEnv = "GITFROK_CONTROLPLANE_ADDR"
	ReaderAddrEnv       = "GITFROK_REPOSITORY_READER_ADDR"
)

// Config is the resolved, self-consistent deployment shape. A Config that exists has already
// survived both refusals.
type Config struct {
	Plane Plane

	// DataplaneAddr is the data plane's single gRPC door (ADR-0041). Set on Data, empty on Control.
	DataplaneAddr string
	// ControlplaneAddr is the control plane's door — the four services ADR-0100 decision 1
	// registers. Set on Control, empty on Data.
	ControlplaneAddr string
	// ReaderAddr is git-storaged's RepositoryReader. Set on Data, empty on Control.
	ReaderAddr string

	// UsedLegacyDataplaneName records that the deployment arrived via GITFROK_PDP_ADDR, so the
	// caller can warn. A compatibility window nobody measures never closes.
	UsedLegacyDataplaneName bool
}

// IsControl reports whether this deployment serves the control plane's route set.
func (c Config) IsControl() bool { return c.Plane == Control }

// ErrRefused marks a configuration this package will not start with. Every error below wraps it, so
// a caller can distinguish "you configured this wrongly" from an operational failure.
var ErrRefused = errors.New("refused")

// Resolve reads the deployment's plane and addresses, and refuses any combination ADR-0094
// decision 5 or ADR-0100 decision 6 forbids.
//
// getenv is injected so the refusals are testable without mutating process state — which matters
// because these two refusals are the enforcement mechanism, not a convenience.
func Resolve(getenv func(string) string) (Config, error) {
	raw := strings.TrimSpace(getenv(PlaneEnv))
	if raw == "" {
		return Config{}, fmt.Errorf("%w: %s is not set; it must be %q or %q. There is deliberately no "+
			"default, because a default would silently choose a route set (ADR-0094 decision 5)",
			ErrRefused, PlaneEnv, Control, Data)
	}

	p := Plane(raw)
	if p != Control && p != Data {
		return Config{}, fmt.Errorf("%w: %s=%q is not a plane; it must be %q or %q",
			ErrRefused, PlaneEnv, raw, Control, Data)
	}

	dataplaneAddr := strings.TrimSpace(getenv(DataplaneAddrEnv))
	legacy := false
	if dataplaneAddr == "" {
		if v := strings.TrimSpace(getenv(LegacyDataplaneAddrEnv)); v != "" {
			dataplaneAddr = v
			legacy = true
		}
	}
	controlplaneAddr := strings.TrimSpace(getenv(ControlplaneAddrEnv))
	readerAddr := strings.TrimSpace(getenv(ReaderAddrEnv))

	cfg := Config{Plane: p, UsedLegacyDataplaneName: legacy}

	switch p {
	case Control:
		// THE REFUSAL ADR-0094 DECISION 5 ASKS FOR, and the one that did not exist before SPEC-0070.
		// A control-plane deployment renders no repository content (decision 4), so a reader address
		// is not merely unnecessary — configuring one means someone intended this deployment to
		// serve routes it must not have, and serving them would put a control-plane process on a
		// data-plane dial that ADR-0011 forbids.
		if readerAddr != "" {
			return Config{}, fmt.Errorf("%w: %s=control must not have %s set. A control-plane "+
				"deployment renders no repository content (ADR-0094 decision 4), and reaching a data "+
				"plane for it is what ADR-0011 forbids. The repository surface is served by a "+
				"data-plane deployment of this same binary",
				ErrRefused, PlaneEnv, ReaderAddrEnv)
		}
		// ADR-0100 decision 6: no data-plane address at all, so the no-dial rule is structural.
		if dataplaneAddr != "" {
			name := DataplaneAddrEnv
			if legacy {
				name = LegacyDataplaneAddrEnv
			}
			return Config{}, fmt.Errorf("%w: %s=control must not have %s set. ADR-0100 decision 6 "+
				"gives a control-plane deployment no data-plane address, so there is nothing to dial "+
				"— which is how ADR-0011's rule becomes structural instead of asserted",
				ErrRefused, PlaneEnv, name)
		}
		if controlplaneAddr == "" {
			return Config{}, fmt.Errorf("%w: %s=control needs %s — the control plane's door serving "+
				"the four services ADR-0100 decision 1 registers. Without it this deployment can "+
				"authorize nothing, and it must not serve requests it cannot check (ADR-0006)",
				ErrRefused, PlaneEnv, ControlplaneAddrEnv)
		}
		cfg.ControlplaneAddr = controlplaneAddr

	case Data:
		// Today's behaviour, preserved for the plane that genuinely needs it.
		if readerAddr == "" {
			return Config{}, fmt.Errorf("%w: %s=data needs %s: without RepositoryReader the browser "+
				"has no data to show", ErrRefused, PlaneEnv, ReaderAddrEnv)
		}
		if dataplaneAddr == "" {
			return Config{}, fmt.Errorf("%w: %s=data needs %s — the data plane's single gRPC door "+
				"(ADR-0041)", ErrRefused, PlaneEnv, DataplaneAddrEnv)
		}
		if controlplaneAddr != "" {
			return Config{}, fmt.Errorf("%w: %s=data must not have %s set. The mirror of ADR-0100 "+
				"decision 6: a data-plane deployment serves no metadata surface, so it needs no "+
				"control-plane door",
				ErrRefused, PlaneEnv, ControlplaneAddrEnv)
		}
		cfg.DataplaneAddr = dataplaneAddr
		cfg.ReaderAddr = readerAddr
	}

	return cfg, nil
}
