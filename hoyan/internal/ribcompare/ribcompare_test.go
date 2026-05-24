package ribcompare

import (
	"path/filepath"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestExpectedRoutes(t *testing.T) {
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	routes := Expected(topo)
	if len(routes) == 0 {
		t.Fatalf("Expected() returned no routes")
	}
	var found bool
	for _, r := range routes {
		if r.Node == "bj-edge1" && r.Prefix == "10.4.1.10/32" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected bj-edge1 route to hz customer host")
	}
}

func TestParseFRR(t *testing.T) {
	data := []byte(`{
	  "totalPrefixCounter": 1,
	  "routes": {
	    "10.4.1.10/32": [
	      {"valid": true, "bestpath": false, "nexthops": [{"ip": "198.18.20.7"}], "path": "65100 4200001004"},
	      {"valid": true, "bestpath": true, "nexthops": [{"ip": "198.18.10.1"}], "path": "65100 4200001004"}
	    ],
	    "10.1.0.0/16": [
	      {"valid": true, "bestpath": true, "nexthops": [{"ip": "0.0.0.0"}], "path": ""}
	    ]
	  }
	}`)
	routes, err := ParseFRR("bj-edge1", data)
	if err != nil {
		t.Fatalf("ParseFRR() error = %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	var foundRemote, foundLocal bool
	for _, route := range routes {
		if route.Prefix == "10.4.1.10/32" && route.NextHop == "198.18.10.1" {
			foundRemote = true
		}
		if route.Prefix == "10.1.0.0/16" && route.NextHop == "" {
			foundLocal = true
		}
	}
	if !foundRemote || !foundLocal {
		t.Fatalf("routes = %#v", routes)
	}
}

func TestCompare(t *testing.T) {
	diffs := Compare(
		[]ExpectedRoute{{Node: "r1", Prefix: "10.0.0.0/24", NextHop: "r2"}},
		[]ActualRoute{{Node: "r1", Prefix: "10.0.0.0/24", NextHop: "r3"}},
	)
	if len(diffs) != 1 {
		t.Fatalf("diffs = %#v", diffs)
	}
}
