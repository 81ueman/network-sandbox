package failure

import (
	"strings"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
	"github.com/81ueman/network-sandbox/hoyan/internal/symbolic"
)

func TestSetAndContext(t *testing.T) {
	failures := SetFromMap(map[string]bool{
		"raw-link":      true,
		"link:prefixed": true,
		"node:a":        true,
		"ignored":       false,
	})
	if !failures.Links["raw-link"] || !failures.Links["prefixed"] || !failures.Nodes["a"] {
		t.Fatalf("SetFromMap() = %#v", failures)
	}
	if failures.Links["ignored"] {
		t.Fatalf("false raw entries should be ignored")
	}

	ctx := Context{
		Failures: failures,
		LinksByName: map[model.LinkID]model.Link{
			"a-b":      {Name: "a-b", A: "a", B: "b"},
			"prefixed": {Name: "prefixed", A: "x", B: "y"},
		},
	}
	if !ctx.NodeFailed("a") || ctx.NodeFailed("b") {
		t.Fatalf("NodeFailed returned unexpected values")
	}
	if !ctx.LinkFailed("raw-link") || !ctx.LinkFailed("prefixed") || !ctx.LinkFailed("a-b") {
		t.Fatalf("LinkFailed did not account for explicit link and endpoint node failures")
	}
}

func TestSetFromElements(t *testing.T) {
	failures := SetFromElements([]solver.FailureElement{
		{Kind: solver.FailureLink, Name: "a-b"},
		{Kind: solver.FailureNode, Name: "b"},
	})
	if !failures.Links["a-b"] || !failures.Nodes["b"] {
		t.Fatalf("SetFromElements() = %#v", failures)
	}
}

func TestBoolExprConvertsCondTree(t *testing.T) {
	expr := BoolExpr(Not(And(LinkVar("a-b"), Or(NodeVar("a"), False()))))
	if expr.Kind != symbolic.KindNot {
		t.Fatalf("expr kind = %s, want not: %s", expr.Kind, expr)
	}
	text := expr.String()
	for _, want := range []string{"link:a-b", "node:a"} {
		if !strings.Contains(text, want) {
			t.Fatalf("BoolExpr() = %s, want %s", text, want)
		}
	}
}

func TestConditionEvaluation(t *testing.T) {
	ctx := Context{
		Failures: Nodes("a"),
		LinksByName: map[model.LinkID]model.Link{
			"a-b": {Name: "a-b", A: "a", B: "b"},
			"b-c": {Name: "b-c", A: "b", B: "c"},
		},
	}
	if LinkVar("a-b").Eval(ctx) {
		t.Fatalf("LinkVar should be false when endpoint node is failed")
	}
	if !LinkVar("b-c").Eval(ctx) {
		t.Fatalf("LinkVar should be true when link and endpoints are up")
	}
	if NodeVar("a").Eval(ctx) || !NodeVar("b").Eval(ctx) {
		t.Fatalf("NodeVar returned unexpected values")
	}
	if Var("a-b").Eval(ctx) {
		t.Fatalf("Var should remain a backward-compatible link condition")
	}
}

func TestExpandLinkVarsEmbedsEndpointNodeConditions(t *testing.T) {
	links := map[model.LinkID]model.Link{
		"a-b": {Name: "a-b", A: "a", B: "b"},
	}
	expanded := ExpandLinkVars(LinkVar("a-b"), links)
	if expanded.Eval(Context{Failures: Nodes("a")}) {
		t.Fatalf("expanded link condition should be false when endpoint node is failed: %s", expanded)
	}
	if !expanded.Eval(Context{Failures: None()}) {
		t.Fatalf("expanded link condition should be true without failures: %s", expanded)
	}

	notExpanded := ExpandLinkVars(Not(LinkVar("a-b")), links)
	if !notExpanded.Eval(Context{Failures: Nodes("a")}) {
		t.Fatalf("expanded NOT(link) should be true when endpoint node is failed: %s", notExpanded)
	}
}
