package builder

import (
	"slices"
	"testing"
)

func baseEnvCfg(env map[string]string) Config {
	return Config{BuildEnv: env}
}

func TestBuildScriptEnvIncludesHermeticBase(t *testing.T) {
	env, err := buildScriptEnv(baseEnvCfg(nil), "/src", "/dest", 1700000000)
	if err != nil {
		t.Fatalf("buildScriptEnv: %v", err)
	}
	want := []string{
		"SOURCE_DIR=/src",
		"DESTDIR=/dest",
		"SOURCE_DATE_EPOCH=1700000000",
		"LC_ALL=C",
		"TZ=UTC",
	}
	for _, w := range want {
		if !slices.Contains(env, w) {
			t.Errorf("env missing %q; got %v", w, env)
		}
	}
}

func TestBuildScriptEnvInjectsDeclaredVars(t *testing.T) {
	cfg := baseEnvCfg(map[string]string{
		"PKM_KACS_TCB_PUBKEY_HEX": "deadbeef",
		"ANOTHER_VAR":             "x=y=z", // value may contain '='
	})
	env, err := buildScriptEnv(cfg, "/src", "/dest", 0)
	if err != nil {
		t.Fatalf("buildScriptEnv: %v", err)
	}
	if !slices.Contains(env, "PKM_KACS_TCB_PUBKEY_HEX=deadbeef") {
		t.Errorf("declared var not injected; got %v", env)
	}
	if !slices.Contains(env, "ANOTHER_VAR=x=y=z") {
		t.Errorf("value with '=' mangled; got %v", env)
	}
}

func TestBuildScriptEnvRejectsReserved(t *testing.T) {
	for _, name := range []string{"PATH", "DESTDIR", "SOURCE_DATE_EPOCH"} {
		_, err := buildScriptEnv(baseEnvCfg(map[string]string{name: "x"}), "/src", "/dest", 0)
		if err == nil {
			t.Errorf("reserved name %q was accepted", name)
		}
	}
}

func TestBuildScriptEnvRejectsInvalidName(t *testing.T) {
	for _, name := range []string{"1ABC", "has-dash", "has space", "", "a.b"} {
		_, err := buildScriptEnv(baseEnvCfg(map[string]string{name: "x"}), "/src", "/dest", 0)
		if err == nil {
			t.Errorf("invalid name %q was accepted", name)
		}
	}
}

func TestBuildScriptEnvDeterministicOrder(t *testing.T) {
	cfg := baseEnvCfg(map[string]string{"B_VAR": "2", "A_VAR": "1", "C_VAR": "3"})
	first, err := buildScriptEnv(cfg, "/src", "/dest", 0)
	if err != nil {
		t.Fatalf("buildScriptEnv: %v", err)
	}
	second, _ := buildScriptEnv(cfg, "/src", "/dest", 0)
	if !slices.Equal(first, second) {
		t.Fatalf("env order not deterministic:\n%v\n%v", first, second)
	}
}
