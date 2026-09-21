package plane_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/plane"
)

// env builds a getenv from a map, so a case states exactly the environment it describes and nothing
// leaks between cases. Mutating the process environment would make these two refusals — the
// enforcement mechanism of ADR-0094 decision 5 — order-dependent.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// SPEC-0070 AC1: one input, two legal values, no default. A default would silently choose a route
// set, which is the failure this refusal exists to prevent.
func TestPlaneMustBeStatedExplicitly(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"absent":         "",
		"whitespace":     "   ",
		"wrong case":     "Control",
		"plausible typo": "controlplane",
		"a third plane":  "management",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := plane.Resolve(env(map[string]string{plane.PlaneEnv: value}))
			if err == nil {
				t.Fatalf("Resolve accepted %s=%q; it must refuse anything but control or data", plane.PlaneEnv, value)
			}
			if !errors.Is(err, plane.ErrRefused) {
				t.Fatalf("error does not wrap ErrRefused: %v", err)
			}
			// The message must name both legal values, or an operator has to read source to fix it.
			for _, want := range []string{string(plane.Control), string(plane.Data)} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not name %q: %v", want, err)
				}
			}
		})
	}
}

// SPEC-0070 AC2 — THE REFUSAL THAT DID NOT EXIST. Before this, main.go required the reader
// unconditionally, so a control-plane deployment could not start at all; now configuring one is
// itself the error, because it means someone intended this deployment to serve repository routes.
func TestControlPlaneRefusesAReaderAddress(t *testing.T) {
	t.Parallel()

	_, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:            string(plane.Control),
		plane.ControlplaneAddrEnv: "controlplane:9095",
		plane.ReaderAddrEnv:       "git-storaged:9000",
	}))
	if err == nil {
		t.Fatal("a control-plane deployment accepted a RepositoryReader address; ADR-0094 decision 5 requires it to refuse")
	}
	if !errors.Is(err, plane.ErrRefused) {
		t.Fatalf("error does not wrap ErrRefused: %v", err)
	}
	if !strings.Contains(err.Error(), plane.ReaderAddrEnv) {
		t.Errorf("refusal does not name the offending variable: %v", err)
	}
}

// ADR-0100 decision 6: no data-plane address at all on the control plane, so ADR-0011's no-dial rule
// is structural rather than asserted. Both spellings must be refused, or the rename opens a hole.
func TestControlPlaneRefusesADataPlaneAddressUnderEitherName(t *testing.T) {
	t.Parallel()

	for name, key := range map[string]string{
		"current name": plane.DataplaneAddrEnv,
		"legacy name":  plane.LegacyDataplaneAddrEnv,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := plane.Resolve(env(map[string]string{
				plane.PlaneEnv:            string(plane.Control),
				plane.ControlplaneAddrEnv: "controlplane:9095",
				key:                       "dataplane:9090",
			}))
			if err == nil {
				t.Fatalf("a control-plane deployment accepted %s; there must be no data-plane address to dial", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("refusal does not name %s: %v", key, err)
			}
		})
	}
}

// SPEC-0070 AC3: the case that used to exit. A control-plane deployment with no reader is the
// correct shape, and it must start.
func TestControlPlaneStartsWithoutAReader(t *testing.T) {
	t.Parallel()

	cfg, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:            string(plane.Control),
		plane.ControlplaneAddrEnv: "controlplane:9095",
	}))
	if err != nil {
		t.Fatalf("a control-plane deployment without a reader was refused, which is the bug SPEC-0070 fixes: %v", err)
	}
	if !cfg.IsControl() {
		t.Error("resolved config is not the control plane")
	}
	if cfg.ReaderAddr != "" || cfg.DataplaneAddr != "" {
		t.Errorf("control-plane config carries a data-plane address: reader=%q dataplane=%q", cfg.ReaderAddr, cfg.DataplaneAddr)
	}
}

// SPEC-0070 AC3 continued: a control-plane deployment still needs its own door, or it can authorize
// nothing — ADR-0006's rule survives the partition.
func TestControlPlaneNeedsItsOwnDoor(t *testing.T) {
	t.Parallel()

	_, err := plane.Resolve(env(map[string]string{plane.PlaneEnv: string(plane.Control)}))
	if err == nil {
		t.Fatal("a control-plane deployment with no control-plane door was accepted; it could authorize nothing")
	}
	if !strings.Contains(err.Error(), plane.ControlplaneAddrEnv) {
		t.Errorf("refusal does not name the missing door: %v", err)
	}
}

// SPEC-0070 AC4: today's behaviour, preserved for the plane that genuinely needs a reader.
func TestDataPlaneRefusesAMissingReader(t *testing.T) {
	t.Parallel()

	_, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:         string(plane.Data),
		plane.DataplaneAddrEnv: "dataplane:9090",
	}))
	if err == nil {
		t.Fatal("a data-plane deployment without a reader was accepted; the browser would have no data to show")
	}
	if !strings.Contains(err.Error(), plane.ReaderAddrEnv) {
		t.Errorf("refusal does not name the missing reader: %v", err)
	}
}

func TestDataPlaneResolves(t *testing.T) {
	t.Parallel()

	cfg, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:         string(plane.Data),
		plane.DataplaneAddrEnv: "dataplane:9090",
		plane.ReaderAddrEnv:    "git-storaged:9000",
	}))
	if err != nil {
		t.Fatalf("a correctly configured data plane was refused: %v", err)
	}
	if cfg.IsControl() {
		t.Error("resolved config claims to be the control plane")
	}
	if cfg.DataplaneAddr != "dataplane:9090" || cfg.ReaderAddr != "git-storaged:9000" {
		t.Errorf("addresses not carried through: %+v", cfg)
	}
	if cfg.UsedLegacyDataplaneName {
		t.Error("the current name was reported as legacy")
	}
}

// The mirror of ADR-0100 decision 6.
func TestDataPlaneRefusesAControlPlaneDoor(t *testing.T) {
	t.Parallel()

	_, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:            string(plane.Data),
		plane.DataplaneAddrEnv:    "dataplane:9090",
		plane.ReaderAddrEnv:       "git-storaged:9000",
		plane.ControlplaneAddrEnv: "controlplane:9095",
	}))
	if err == nil {
		t.Fatal("a data-plane deployment accepted a control-plane door; it serves no metadata surface")
	}
}

// ADR-0100 decision 5: the rename is additive for one release, and the legacy arrival is REPORTED
// rather than silent — a compatibility window nobody measures never closes.
func TestLegacyDataplaneNameStillWorksAndIsReported(t *testing.T) {
	t.Parallel()

	cfg, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:               string(plane.Data),
		plane.LegacyDataplaneAddrEnv: "dataplane:9090",
		plane.ReaderAddrEnv:          "git-storaged:9000",
	}))
	if err != nil {
		t.Fatalf("the legacy name was refused during its compatibility window: %v", err)
	}
	if cfg.DataplaneAddr != "dataplane:9090" {
		t.Errorf("legacy address not carried through: %q", cfg.DataplaneAddr)
	}
	if !cfg.UsedLegacyDataplaneName {
		t.Error("a legacy arrival was not reported, so nothing would ever warn and the window would not close")
	}
}

// The current name wins, so a deployment mid-rename with both set is unambiguous.
func TestCurrentNameWinsOverLegacy(t *testing.T) {
	t.Parallel()

	cfg, err := plane.Resolve(env(map[string]string{
		plane.PlaneEnv:               string(plane.Data),
		plane.DataplaneAddrEnv:       "new:9090",
		plane.LegacyDataplaneAddrEnv: "old:9090",
		plane.ReaderAddrEnv:          "git-storaged:9000",
	}))
	if err != nil {
		t.Fatalf("both names set was refused: %v", err)
	}
	if cfg.DataplaneAddr != "new:9090" {
		t.Errorf("legacy name won over the current one: %q", cfg.DataplaneAddr)
	}
	if cfg.UsedLegacyDataplaneName {
		t.Error("reported legacy when the current name was used")
	}
}
