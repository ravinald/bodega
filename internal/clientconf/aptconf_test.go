package clientconf

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAptConfigLoadsAsAPT holds what apt-config dump answered for each body
// as the file APT_CONFIG names, in a debian:trixie container: whether apt
// loaded it, and the Acquire::https::CAInfo it ended with, unscoped and
// scoped to bodega.example.com. The port is read from the APT 3.0.3 source;
// this table is how a change to it is caught on a host with no apt.
func TestAptConfigLoadsAsAPT(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"inc/ok.conf":      "Acquire::https::CAInfo \"/inc-ok.pem\";\n",
		"inc/bad.conf":     "Acquire::Retries \"3\" extra;\n",
		"inc/dir/10a.conf": "Acquire::https::CAInfo \"/inc-dir-a.pem\";\n",
		"inc/dir/20b":      "Acquire::https::CAInfo \"/inc-dir-b.pem\";\n",
		"inc/dir/30c.bak":  "Acquire::https::CAInfo \"/inc-dir-c.pem\";\n",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(root, "apt-config")
	for _, tc := range []struct {
		body     string
		loads    bool
		ca, host string
	}{
		{"Acquire::https::CAInfo \"/a.pem\";\n", true, "/a.pem", ""},
		{"Acquire::https::CAInfo \"/unused.pem\"\n", false, "", ""},
		{"Acquire::Retries \"3\" extra;\n", false, "", ""},
		{"Acquire { https { CAInfo \"/b.pem\"; }; };\n", true, "/b.pem", ""},
		{"Acquire::https { CAInfo \"/c.pem\"; }\n", true, "/c.pem", ""},
		{"// Acquire::https::CAInfo \"/no.pem\";\nAcquire::Retries \"3\";\n", true, "", ""},
		{"# Acquire::https::CAInfo \"/no.pem\";\n", true, "", ""},
		{"Acquire::Retries \"3\"; # Acquire::https::CAInfo \"/no.pem\";\n", true, "", ""},
		{"Acquire::https::CAInfo \"/d.pem\"; /* x */ Acquire::Retries \"3\";\n", true, "/d.pem", ""},
		{"/* Acquire::https::CAInfo \"/no.pem\";\n*/ Acquire::https::CAInfo \"/e.pem\";\n", true, "/e.pem", ""},
		{"Acquire::https::CAInfo \"/f.pem\";\n#clear Acquire::https;\n", true, "", ""},
		{"Acquire::https::CAInfo \"/f.pem\";\n#clear Acquire::https::;\n", true, "/f.pem", ""},
		{"Acquire::https::CAInfo\n  \"/g.pem\"\n;\n", true, "/g.pem", ""},
		{"Acquire::https::CAInfo \"/h\" \"i.pem\";\n", true, "/h i.pem", ""},
		{"Acquire::https::CAInfo /j.pem;\n", true, "/j.pem", ""},
		{"Acquire::https::CAInfo \"/k%20l.pem\";\n", true, "/k%20l.pem", ""},
		{"Acquire::https::CAInfo /k%20l.pem;\n", true, "/k l.pem", ""},
		{"acquire::HTTPS::cainfo \"/m.pem\";\n", true, "/m.pem", ""},
		{"{ };\n", false, "", ""},
		{"Acquire::https::CAInfo \"/n.pem\";;\n", true, "/n.pem", ""},
		{"Acquire::https::CAInfo \"/o.pem\"; }\n", true, "/o.pem", ""},
		{"Acquire { #clear Acquire; };\n", false, "", ""},
		{"#bogus x;\n", true, "", ""},
		{"#clear;\n", false, "", ""},
		{"Acquire::https::CAInfo \"/p.pem\n\";\n", false, "", ""},
		{"Acquire::https::CAInfo \"http://x/y\";\n", true, "http://x/y", ""},
		{"Acquire::https::CAInfo http://x/y;\n", false, "", ""},
		{"Acquire::https::CAInfo \"/q.pem\" ; Foo \"a;b\";\n", true, "/q.pem", ""},
		{"Acquire::https::CAInfo \"/r.pem\";\nFoo \"bar\n", false, "", ""},
		{"Acquire::https::CAInfo \"/s.pem\";\nFoo {\n", true, "/s.pem", ""},
		{"Acquire::https::CAInfo \"/t.pem\";\nFoo:: \"a\";\nFoo:: \"b\";\n", true, "/t.pem", ""},
		{"Acquire::https { \"/u.pem\"; };\n", true, "", ""},
		{"\"/v.pem\";\n", true, "", ""},
		{"Acquire::https::CAInfo \"/w.pem\";\r\n", true, "/w.pem", ""},
		{"Acquire::https::CAInfo\t\"/x.pem\";\n", true, "/x.pem", ""},
		{"Acquire::https::CAInfo [a b];\n", true, "[a b]", ""},
		{"Acquire::https::CAInfo \"/y.pem\" \"extra\" z;\n", false, "", ""},
		{"Acquire::https \"x\" { CAInfo \"/z.pem\"; };\n", true, "/z.pem", ""},
		{"Acquire::https::CAInfo \"/aa.pem\";\n#include \"/inc/missing.conf\";\n", false, "", ""},
		{"#include \"/inc/ok.conf\";\n", true, "/inc-ok.pem", ""},
		{"#include \"/inc/bad.conf\";\n", false, "", ""},
		{"#include \"/inc/dir/\";\n", true, "/inc-dir-b.pem", ""},
		{"Acquire::https::CAInfo \"/ab.pem\"; #clear Acquire::https::CAInfo;\n", true, "", ""},
		{"Acquire::https::CAInfo \"/ac.pem\";\n#clearx Acquire;\n", false, "", ""},
		{"Acquire::https::CAInfo \"/ad.pem\"; x#y \"1\";\n", false, "", ""},
		{"Acquire::https::CAInfo \"\";\n", true, "", ""},
		{"Acquire::https::CAInfo \"/ae.pem\";\nAcquire::https::CAInfo;\n", true, "/ae.pem", ""},
		{"Acquire::https::bodega.example.com::CAInfo \"/af.pem\";\n", true, "", "/af.pem"},
		{"Acquire::https::CAInfo \"/ag.pem\"; /* open\n", true, "/ag.pem", ""},
		{"Acquire::https::CAInfo \"/ah.pem\";\nFoo \"a\" { Bar \"b\"; };\n", true, "/ah.pem", ""},
		{"Acquire::https::CAInfo \"/ai.pem\";\n  \n;\n", true, "/ai.pem", ""},
		{"Acquire::https::CAInfo \"/aj.pem\";\n};\n", true, "/aj.pem", ""},
		{"Acquire\n{\n  https\n  {\n    CAInfo \"/ak.pem\";\n  }\n}\n", true, "/ak.pem", ""},
		{"Acquire::https::CAInfo \"/al.pem\"", false, "", ""},
		{"Acquire::https::CAInfo \"a//b.pem\";\n", true, "a//b.pem", ""},
		{"Acquire::https::CAInfo \"/am.pem\"; Foo \"x\" // c\n;\n", true, "/am.pem", ""},
		{"Acquire::https::CAInfo::Sub \"/an.pem\";\n#clear acquire::https::cainfo;\n", true, "", ""},
	} {
		if err := os.WriteFile(file, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		conf, err := LoadAptConfig(root, func(key string) string {
			if key == "APT_CONFIG" {
				return file
			}
			return ""
		})
		if (err == nil) != tc.loads {
			t.Errorf("%q: err=%v; apt loads it: %v", tc.body, err, tc.loads)
			continue
		}
		if got := conf["acquire::https::cainfo"].Value; got != tc.ca {
			t.Errorf("%q: CAInfo=%q; apt has %q", tc.body, got, tc.ca)
		}
		if got := conf["acquire::https::bodega.example.com::cainfo"].Value; got != tc.host {
			t.Errorf("%q: host CAInfo=%q; apt has %q", tc.body, got, tc.host)
		}
	}
}
