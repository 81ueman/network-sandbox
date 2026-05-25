package failure

import (
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type Cond interface {
	Eval(ctx Context) bool
	Key() string
	String() string
}

type condVarKind string

const (
	condVarLink condVarKind = "link"
	condVarNode condVarKind = "node"
)

type trueCond struct{}
type falseCond struct{}
type varCond struct {
	kind condVarKind
	name string
}
type andCond []Cond
type orCond []Cond
type notCond struct{ c Cond }

func True() Cond           { return trueCond{} }
func False() Cond          { return falseCond{} }
func Var(name string) Cond { return LinkVar(name) }
func LinkVar(name string) Cond {
	return varCond{kind: condVarLink, name: name}
}
func NodeVar(name string) Cond {
	return varCond{kind: condVarNode, name: name}
}
func And(cs ...Cond) Cond { return flattenAnd(cs) }
func Or(cs ...Cond) Cond  { return flattenOr(cs) }
func Not(c Cond) Cond     { return simplifyNot(c) }

func (trueCond) Eval(Context) bool { return true }
func (trueCond) Key() string       { return "true" }
func (trueCond) String() string    { return "true" }

func (falseCond) Eval(Context) bool { return false }
func (falseCond) Key() string       { return "false" }
func (falseCond) String() string    { return "false" }

func (c varCond) Eval(ctx Context) bool {
	switch c.kind {
	case condVarNode:
		return !ctx.NodeFailed(model.NodeID(c.name))
	case condVarLink:
		return !ctx.LinkFailed(model.LinkID(c.name))
	default:
		return true
	}
}
func (c varCond) Key() string    { return "var:" + string(c.kind) + ":" + c.name }
func (c varCond) String() string { return string(c.kind) + ":" + c.name }

func (c andCond) Eval(ctx Context) bool {
	for _, x := range c {
		if !x.Eval(ctx) {
			return false
		}
	}
	return true
}
func (c andCond) Key() string    { return joinCondKey("and", c) }
func (c andCond) String() string { return joinCond(" && ", c) }

func (c orCond) Eval(ctx Context) bool {
	for _, x := range c {
		if x.Eval(ctx) {
			return true
		}
	}
	return false
}
func (c orCond) Key() string    { return joinCondKey("or", c) }
func (c orCond) String() string { return joinCond(" || ", c) }

func (c notCond) Eval(ctx Context) bool {
	return !c.c.Eval(ctx)
}
func (c notCond) Key() string    { return "not(" + c.c.Key() + ")" }
func (c notCond) String() string { return "!(" + c.c.String() + ")" }

func flattenAnd(cs []Cond) Cond {
	var out []Cond
	seen := map[string]bool{}
	for _, c := range cs {
		c = normalizeCond(c)
		switch x := c.(type) {
		case trueCond:
			continue
		case falseCond:
			return falseCond{}
		case andCond:
			for _, child := range x {
				if seen[child.Key()] {
					continue
				}
				seen[child.Key()] = true
				out = append(out, child)
			}
			continue
		}
		if seen[c.Key()] {
			continue
		}
		seen[c.Key()] = true
		out = append(out, c)
	}
	if len(out) == 0 {
		return trueCond{}
	}
	if len(out) == 1 {
		return out[0]
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key() < out[j].Key()
	})
	return andCond(out)
}

func flattenOr(cs []Cond) Cond {
	var out []Cond
	seen := map[string]bool{}
	for _, c := range cs {
		c = normalizeCond(c)
		switch x := c.(type) {
		case trueCond:
			return trueCond{}
		case falseCond:
			continue
		case orCond:
			for _, child := range x {
				if seen[child.Key()] {
					continue
				}
				seen[child.Key()] = true
				out = append(out, child)
			}
			continue
		}
		if seen[c.Key()] {
			continue
		}
		seen[c.Key()] = true
		out = append(out, c)
	}
	if len(out) == 0 {
		return falseCond{}
	}
	if len(out) == 1 {
		return out[0]
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key() < out[j].Key()
	})
	return orCond(out)
}

func simplifyNot(c Cond) Cond {
	c = normalizeCond(c)
	switch x := c.(type) {
	case trueCond:
		return falseCond{}
	case falseCond:
		return trueCond{}
	case notCond:
		return x.c
	default:
		return notCond{c: c}
	}
}

func normalizeCond(c Cond) Cond {
	switch x := c.(type) {
	case andCond:
		return flattenAnd(x)
	case orCond:
		return flattenOr(x)
	case notCond:
		return simplifyNot(x.c)
	default:
		return c
	}
}

func joinCondKey(op string, cs []Cond) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.Key())
	}
	return op + "(" + strings.Join(parts, ",") + ")"
}

func joinCond(sep string, cs []Cond) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.String())
	}
	return "(" + strings.Join(parts, sep) + ")"
}
