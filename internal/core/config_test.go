package core

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigValid(t *testing.T) {
	if err := DefaultConfig().validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(t0, key(0), nil, rand.New(rand.NewPCG(1, 1)), &fakeVerifier{}, newSink()); err != nil {
		t.Fatal(err)
	}
	if _, err := New(t0, key(0), nil, nil, &fakeVerifier{}, newSink()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("nil Rand accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	cases := map[string]func(*Config){
		"Dlo over D":                func(c *Config) { c.Params.Dlo = 7 },
		"D over Dhi":                func(c *Config) { c.Params.D = 13 },
		"Dout at Dlo":               func(c *Config) { c.Params.Dout = 4 },
		"Dout over D/2":             func(c *Config) { c.Params.D, c.Params.Dlo, c.Params.Dout = 6, 5, 4 },
		"Dscore over Dhi":           func(c *Config) { c.Params.Dscore = 13 },
		"negative Dlazy":            func(c *Config) { c.Params.Dlazy = -1 },
		"GossipFactor over 1":       func(c *Config) { c.Params.GossipFactor = 1.5 },
		"GossipFactor NaN":          func(c *Config) { c.Params.GossipFactor = math.NaN() },
		"zero heartbeat":            func(c *Config) { c.HeartbeatInterval = 0 },
		"negative delay":            func(c *Config) { c.HeartbeatInitialDelay = -1 },
		"window over SeenTTL":       func(c *Config) { c.MaxSkew = time.Minute + time.Nanosecond },
		"history under gossip":      func(c *Config) { c.HistoryLength = 2 },
		"zero MaxSeen":              func(c *Config) { c.MaxSeen = 0 },
		"negative MaxTopics":        func(c *Config) { c.MaxTopics = -1 },
		"negative MaxPeers":         func(c *Config) { c.MaxPeers = -1 },
		"negative MaxPeerTopics":    func(c *Config) { c.MaxPeerTopics = -1 },
		"GossipPeers under Dlazy":   func(c *Config) { c.Params.GossipPeers = 5 },
		"zero GossipPeers":          func(c *Config) { c.Params.GossipPeers = 0 },
		"ReaderWork under PeerWork": func(c *Config) { c.ReaderWork = c.PeerWork - 1 },
		"ReaderWork under 64 units": func(c *Config) { c.ReaderWork = 63; c.PeerWork = 63 },
		"share over half":           func(c *Config) { c.MaxPeerValidating = c.MaxValidating/2 + 1 },
		"byte share over half":      func(c *Config) { c.MaxPeerValidatingBytes = c.MaxValidatingBytes/2 + 1 },
		"tiny MaxMessageSize":       func(c *Config) { c.MaxMessageSize = 100 },
		"cache under a message":     func(c *Config) { c.MaxCacheBytes = c.MaxMessageSize - 1 },
		"tiny MaxControlSize":       func(c *Config) { c.MaxControlSize = minControlSize - 1 },
		"IDONTWANT threshold":       func(c *Config) { c.IDontWantThreshold = 12 * 32 },
		"zero IDontWantTTL":         func(c *Config) { c.IDontWantTTL = 0 },
		"score thresholds":          func(c *Config) { c.Score = scoringConfig().Score; c.Score.Thresholds.Gossip = 0 },
	}
	for name, mutate := range cases {
		cfg := DefaultConfig()
		mutate(cfg)
		if err := cfg.validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	boot := DefaultConfig()
	boot.Params = Params{Dscore: 0, GossipFactor: 0.25}
	if err := boot.validate(); err != nil {
		t.Fatalf("bootstrapper mode D = Dlo = Dhi = Dout = 0: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"no cap on peers and topics": func(c *Config) { c.MaxPeers, c.MaxTopics = 0, 0 },
		"MaxTopics over 32":          func(c *Config) { c.MaxTopics = 33 },
		"no other topics kept":       func(c *Config) { c.MaxPeerTopics = 0 },
		"share at half":              func(c *Config) { c.MaxPeerValidating = c.MaxValidating / 2 },
	} {
		cfg := DefaultConfig()
		mutate(cfg)
		if err := cfg.validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	half := DefaultConfig()
	half.Params.D, half.Params.Dlo, half.Params.Dout = 6, 5, 3
	if err := half.validate(); err != nil {
		t.Fatalf("Dout = D/2 is allowed by the spec: %v", err)
	}
}

func TestTopicConfigValidation(t *testing.T) {
	off := DefaultConfig()
	off.Score = nil // topic score parameters need scoring on
	f := newFixture(t, off)
	bad := []*TopicConfig{
		{Params: &Params{D: 1, Dlo: 2, Dhi: 3}},
		{MaxMessageSize: 1<<20 + 1},
		{MaxMessageSize: 10},
		{Score: topicScore()},
	}
	for i, tc := range bad {
		if err := f.r.Join(f.now, T, tc); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if f.r.Stats().Topics != 0 {
		t.Fatal("failed join left state")
	}
	f.join(T, &TopicConfig{Params: &Params{D: 3, Dlo: 2, Dhi: 4, Dlazy: 3, Dscore: 2, Dout: 1, GossipPeers: 3}, MaxMessageSize: 4096})
	if tp := f.r.topics[T]; tp.params.D != 3 || tp.maxSize != 4096 {
		t.Fatal("topic config not applied")
	}
}

// TestPureImports keeps the core free of goroutines, channels, clocks, global randomness, I/O and locks.
func TestPureImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbiddenPkg := map[string]bool{"net": true, "os": true, "sync": true, "sync/atomic": true, "math/rand": true,
		"math/rand/v2": true, "io": true, "unsafe": true, "reflect": true}
	forbiddenTime := map[string]bool{"Now": true, "Since": true, "Until": true, "Sleep": true, "After": true,
		"AfterFunc": true, "Tick": true, "NewTimer": true, "NewTicker": true}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if forbiddenPkg[path] {
				t.Errorf("%s imports %s", name, path)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GoStmt, *ast.ChanType, *ast.SelectStmt:
				t.Errorf("%s: goroutine or channel at %v", name, n.Pos())
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok && id.Name == "time" && forbiddenTime[n.Sel.Name] {
					t.Errorf("%s uses time.%s", name, n.Sel.Name)
				}
			}
			return true
		})
	}
	if checked < 5 {
		t.Fatalf("only %d files checked", checked)
	}
}
