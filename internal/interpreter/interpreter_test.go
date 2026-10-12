package interpreter

import (
	"fmt"
	"testing"

	"github.com/aliyun/credagent/internal/osutil"
)

func TestMain(m *testing.M) {
	// Tests rely on PATH membership for valid-interpreter-path checks.
	// Simulate a typical Linux PATH so paths like /usr/bin/python3 are recognized.
	osutil.SetSystemPATH("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	m.Run()
}

// TestNewInterpreter_FactoryDecision verifies that NewInterpreter wraps a path
// as an Interpreter ONLY when (a) the basename matches a known interpreter
// family AND (b) the path is in a recognized interpreter location.
//
// The path filter is what prevents user binaries like /home/x/bin/python1
// from being mis-classified as interpreters and subjected to stricter checks
// (e.g. PYTHONPATH detection) when they're really just regular binaries.
func TestNewInterpreter_FactoryDecision(t *testing.T) {
	type want struct {
		concrete any // concrete type expected, e.g. (*Python)(nil); nil means "factory returns nil"
	}
	cases := []struct {
		name          string
		path          string
		want          want
		reasonIfFails string
	}{
		// Standard system paths (must be in PATH set by TestMain) — wrap as the right concrete type.
		{"system python3", "/usr/bin/python3", want{(*Python)(nil)}, ""},
		{"system python3.12", "/usr/bin/python3.12", want{(*Python)(nil)}, ""},

		{"system node", "/usr/bin/node", want{(*Node)(nil)}, ""},
		{"system java", "/usr/bin/java", want{(*Java)(nil)}, ""},
		{"local python", "/usr/local/bin/python3", want{(*Python)(nil)}, ""},

		// /opt/X/bin is NOT in PATH by default → must NOT wrap unless registered via globalConfig
		{"opt python (not in PATH)", "/opt/python3.12/bin/python3", want{nil}, "not in system PATH; use globalConfig.TrustedPaths to register"},

		// Name matches interpreter family BUT path is non-standard → must NOT wrap.
		{"user python in /home", "/home/user/bin/python", want{nil}, "non-standard path"},
		{"user python in /tmp", "/tmp/userbin/python", want{nil}, "non-standard path"},

		// Name looks similar but is NOT an interpreter → must NOT wrap (false positive prevention).
		{"system pythonista", "/usr/bin/pythonista", want{nil}, "not an interpreter, just name starts with python"},
		{"system perldoc", "/usr/bin/perldoc", want{nil}, "perl tool, not perl interpreter"},
		{"system nodemon", "/usr/bin/nodemon", want{nil}, "node tool, not node interpreter"},
		{"system phpstorm", "/usr/bin/phpstorm", want{nil}, "IDE, not php interpreter"},
		{"system python-wrapper", "/usr/bin/python-wrapper", want{nil}, "wrapper script, not interpreter"},

		// Name doesn't match any family → must NOT wrap regardless of path.
		{"system cat", "/usr/bin/cat", want{nil}, "cat is not an interpreter family"},
		{"system sudo", "/usr/bin/sudo", want{nil}, ""},
		{"user binary", "/home/user/bin/mytool", want{nil}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewInterpreter(tc.path, 12345)
			if tc.want.concrete == nil {
				if got != nil {
					t.Errorf("NewInterpreter(%q) = %T, want nil (%s)", tc.path, got, tc.reasonIfFails)
				}
				return
			}
			if got == nil {
				t.Fatalf("NewInterpreter(%q) = nil, want %T (%s)", tc.path, tc.want.concrete, tc.reasonIfFails)
			}
			gotType := reflectTypeOf(got)
			wantType := reflectTypeOf(tc.want.concrete)
			if gotType != wantType {
				t.Errorf("NewInterpreter(%q) returned %s, want %s", tc.path, gotType, wantType)
			}
			if got.GetPath() != tc.path {
				t.Errorf("NewInterpreter(%q).GetPath() = %q, want %q", tc.path, got.GetPath(), tc.path)
			}
		})
	}
}

func reflectTypeOf(v any) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", v)
}

// TestNewInterpreter_WithGlobalConfig verifies that a custom interpreter path
// registered in the global interpreter config is recognized.
func TestNewInterpreter_WithGlobalConfig(t *testing.T) {
	prev := globalConfig
	t.Cleanup(func() { globalConfig = prev })

	SetConfig(&Config{
		TrustedPaths: map[string][]string{
			"python": {"/custom/python3.12"},
			"node":   {"/usr/local/bin/npx", "/usr/local/bin/tsx"},
		},
	})

	got := NewInterpreter("/custom/python3.12", 1)
	if got == nil {
		t.Fatal("NewInterpreter(/custom/python3.12) = nil, want *Python via globalConfig.TrustedPaths")
	}
	if _, ok := got.(*Python); !ok {
		t.Errorf("unexpected concrete type: %T (want *Python)", got)
	}

	// A different custom path NOT in trusted list should still fall back to Binary.
	if got := NewInterpreter("/other/python3.12", 1); got != nil {
		t.Errorf("NewInterpreter(/other/python3.12) = %T, want nil", got)
	}

	// exe_paths: npx configured as node family
	got = NewInterpreter("/usr/local/bin/npx", 1)
	if got == nil {
		t.Fatal("NewInterpreter(/usr/local/bin/npx) = nil, want *Node via exe_paths")
	}
	if _, ok := got.(*Node); !ok {
		t.Errorf("unexpected concrete type: %T (want *Node)", got)
	}

	// exe_paths: tsx configured as node family
	got = NewInterpreter("/usr/local/bin/tsx", 1)
	if got == nil {
		t.Fatal("NewInterpreter(/usr/local/bin/tsx) = nil, want *Node via exe_paths")
	}
	if _, ok := got.(*Node); !ok {
		t.Errorf("unexpected concrete type: %T (want *Node)", got)
	}

	// Not in exe_paths → nil
	if got := NewInterpreter("/usr/local/bin/unknown-tool", 1); got != nil {
		t.Errorf("NewInterpreter(/usr/local/bin/unknown-tool) = %T, want nil", got)
	}
}

// Sanity check: matchFamily still recognizes basic interpreter names.
func TestMatchFamily_Sanity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Exact matches
		{"python", "python"},
		{"python2", "python"},
		{"python3", "python"},
		{"PYTHON3", "python"}, // case-insensitive
		{"node", "node"},
		{"nodejs", "node"},
		{"bash", ""},

		{"java", "java"},
		{"ruby", "ruby"},
		{"perl", "perl"},
		{"php", "php"},
		{"php-fpm", "php"},

		// Version suffixes (regex)
		{"python3.12", "python"},
		{"python3.11.5", "python"},
		{"ruby3.2", "ruby"},
		{"perl5.38", "perl"},
		{"php8.1", "php"},

		// Must NOT match (false positive prevention)
		{"pythonista", ""},
		{"python-wrapper", ""},
		{"python_launcher", ""},
		{"perldoc", ""},
		{"perlcritic", ""},
		{"phpstorm", ""},
		{"php-cs-fixer", ""},
		{"rubymine", ""},
		{"nodemon", ""},
		{"npx", ""}, // not built-in; use exe_paths config
		{"cat", ""},
		{"sudo", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := matchFamily(tc.in); got != tc.want {
			t.Errorf("matchFamily(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Ensure *Interpreter still satisfies osutil.BinaryInf after recent changes.
var _ osutil.BinaryInf = (*Interpreter)(nil)
