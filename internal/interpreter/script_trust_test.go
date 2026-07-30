package interpreter

import (
	"testing"

	"github.com/alibaba/CredAgent/internal/osutil"
)

func TestPython_ExtractScriptPath(t *testing.T) {
	p := &Python{}
	cases := []struct {
		name       string
		args       []string
		wantPath   string
		wantInline bool
	}{
		{"simple script", []string{"script.py"}, "script.py", false},
		{"absolute path", []string{"/usr/local/bin/app.py"}, "/usr/local/bin/app.py", false},
		{"with flags", []string{"-u", "-B", "script.py", "arg1"}, "script.py", false},
		{"inline -c", []string{"-c", "print('hello')"}, "", true},
		{"module -m", []string{"-m", "http.server"}, "", true},
		{"stdin dash", []string{"-"}, "-", false},
		{"double dash", []string{"--", "script.py"}, "script.py", false},
		{"W flag with value", []string{"-W", "ignore", "script.py"}, "script.py", false},
		{"no args", []string{}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, inline := p.extractScriptPath(tc.args)
			if path != tc.wantPath || inline != tc.wantInline {
				t.Errorf("extractScriptPath(%v) = (%q, %v), want (%q, %v)",
					tc.args, path, inline, tc.wantPath, tc.wantInline)
			}
		})
	}
}

func TestNode_ExtractScriptPath(t *testing.T) {
	n := &Node{}
	cases := []struct {
		name       string
		args       []string
		wantPath   string
		wantInline bool
	}{
		{"simple script", []string{"app.js"}, "app.js", false},
		{"eval -e", []string{"-e", "console.log(1)"}, "", true},
		{"eval --eval", []string{"--eval", "console.log(1)"}, "", true},
		{"print -p", []string{"-p", "1+1"}, "", true},
		{"with require", []string{"-r", "dotenv/config", "app.js"}, "app.js", false},
		{"stdin dash", []string{"-"}, "-", false},
		{"double dash", []string{"--", "app.js"}, "app.js", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, inline := n.extractScriptPath(tc.args)
			if path != tc.wantPath || inline != tc.wantInline {
				t.Errorf("extractScriptPath(%v) = (%q, %v), want (%q, %v)",
					tc.args, path, inline, tc.wantPath, tc.wantInline)
			}
		})
	}
}

func TestRuby_ExtractScriptPath(t *testing.T) {
	rb := &Ruby{}
	cases := []struct {
		name       string
		args       []string
		wantPath   string
		wantInline bool
	}{
		{"simple script", []string{"app.rb"}, "app.rb", false},
		{"inline -e", []string{"-e", "puts 1"}, "", true},
		{"with require", []string{"-r", "json", "app.rb"}, "app.rb", false},
		{"with include", []string{"-I", "lib", "app.rb"}, "app.rb", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, inline := rb.extractScriptPath(tc.args)
			if path != tc.wantPath || inline != tc.wantInline {
				t.Errorf("extractScriptPath(%v) = (%q, %v), want (%q, %v)",
					tc.args, path, inline, tc.wantPath, tc.wantInline)
			}
		})
	}
}

func TestPerl_ExtractScriptPath(t *testing.T) {
	p := &Perl{}
	cases := []struct {
		name       string
		args       []string
		wantPath   string
		wantInline bool
	}{
		{"simple script", []string{"app.pl"}, "app.pl", false},
		{"inline -e", []string{"-e", "print 1"}, "", true},
		{"inline -E", []string{"-E", "say 1"}, "", true},
		{"with module", []string{"-M", "Data::Dumper", "app.pl"}, "app.pl", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, inline := p.extractScriptPath(tc.args)
			if path != tc.wantPath || inline != tc.wantInline {
				t.Errorf("extractScriptPath(%v) = (%q, %v), want (%q, %v)",
					tc.args, path, inline, tc.wantPath, tc.wantInline)
			}
		})
	}
}

func TestPHP_ExtractScriptPath(t *testing.T) {
	p := &PHP{}
	cases := []struct {
		name       string
		args       []string
		wantPath   string
		wantInline bool
	}{
		{"simple script", []string{"app.php"}, "app.php", false},
		{"inline -r", []string{"-r", "echo 1;"}, "", true},
		{"with -d", []string{"-d", "display_errors=1", "app.php"}, "app.php", false},
		{"with -c", []string{"-c", "/etc/php.ini", "app.php"}, "app.php", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, inline := p.extractScriptPath(tc.args)
			if path != tc.wantPath || inline != tc.wantInline {
				t.Errorf("extractScriptPath(%v) = (%q, %v), want (%q, %v)",
					tc.args, path, inline, tc.wantPath, tc.wantInline)
			}
		})
	}
}

func TestJava_ExtractScriptPath(t *testing.T) {
	j := &Java{}
	cases := []struct {
		name       string
		args       []string
		wantPath   string
		wantInline bool
	}{
		{"jar file", []string{"-jar", "/opt/app/server.jar"}, "/opt/app/server.jar", false},
		{"jar with jvm opts", []string{"-Xmx512m", "-Dprop=val", "-jar", "app.jar"}, "app.jar", false},
		{"classpath + main class", []string{"-cp", "lib.jar:.", "com.example.Main"}, "", false},
		{"module path", []string{"--module-path", "mods", "-m", "com.app/com.app.Main"}, "", false},
		{"no args", []string{}, "", false},
		{"jar missing path", []string{"-jar"}, "", false},
		{"agent + jar", []string{"-javaagent:agent.jar", "-jar", "app.jar"}, "app.jar", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, inline := j.extractScriptPath(tc.args)
			if path != tc.wantPath || inline != tc.wantInline {
				t.Errorf("extractScriptPath(%v) = (%q, %v), want (%q, %v)",
					tc.args, path, inline, tc.wantPath, tc.wantInline)
			}
		})
	}
}

func TestCheckScriptPathTrust(t *testing.T) {
	cases := []struct {
		name           string
		path           string
		trustedScripts []string
		wantLevel      osutil.RiskLevel
	}{
		{"tmp path untrusted", "/tmp/evil.py", nil, osutil.Untrusted},
		{"home path untrusted", "/home/user/script.py", nil, osutil.Untrusted},
		{"dev_shm untrusted", "/dev/shm/payload.sh", nil, osutil.Untrusted},
		{"var_tmp untrusted", "/var/tmp/x.pl", nil, osutil.Untrusted},
		{"run_user untrusted", "/run/user/1000/x.sh", nil, osutil.Untrusted},
		{"tmp but trusted via allowlist", "/tmp/special.py", []string{"/tmp/special.py"}, osutil.Trusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := osutil.CheckScriptPathTrust(tc.path, "", tc.trustedScripts)
			if result.Level != tc.wantLevel {
				t.Errorf("CheckScriptPathTrust(%q) = %v (reason=%q), want %v",
					tc.path, result.Level, result.Reason, tc.wantLevel)
			}
		})
	}
}
