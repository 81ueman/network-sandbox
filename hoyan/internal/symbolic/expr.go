package symbolic

import (
	"sort"
	"strings"
)

type VarKind string

const (
	VarLink VarKind = "link"
	VarNode VarKind = "node"
)

type Kind string

const (
	KindTrue  Kind = "true"
	KindFalse Kind = "false"
	KindVar   Kind = "var"
	KindAnd   Kind = "and"
	KindOr    Kind = "or"
	KindNot   Kind = "not"
)

type Expr struct {
	Kind     Kind
	VarKind  VarKind
	Name     string
	Children []Expr
}

func True() Expr {
	return Expr{Kind: KindTrue}
}

func False() Expr {
	return Expr{Kind: KindFalse}
}

func Var(kind VarKind, name string) Expr {
	return Expr{Kind: KindVar, VarKind: kind, Name: name}
}

func LinkVar(name string) Expr {
	return Var(VarLink, name)
}

func NodeVar(name string) Expr {
	return Var(VarNode, name)
}

func And(xs ...Expr) Expr {
	var out []Expr
	seen := map[string]bool{}
	for _, x := range xs {
		x = x.Normalize()
		switch x.Kind {
		case KindTrue:
			continue
		case KindFalse:
			return False()
		case KindAnd:
			for _, child := range x.Children {
				key := child.Key()
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, child)
			}
			continue
		}
		key := x.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, x)
	}
	if len(out) == 0 {
		return True()
	}
	if len(out) == 1 {
		return out[0]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return Expr{Kind: KindAnd, Children: out}
}

func Or(xs ...Expr) Expr {
	var out []Expr
	seen := map[string]bool{}
	for _, x := range xs {
		x = x.Normalize()
		switch x.Kind {
		case KindTrue:
			return True()
		case KindFalse:
			continue
		case KindOr:
			for _, child := range x.Children {
				key := child.Key()
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, child)
			}
			continue
		}
		key := x.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, x)
	}
	if len(out) == 0 {
		return False()
	}
	if len(out) == 1 {
		return out[0]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return Expr{Kind: KindOr, Children: out}
}

func Not(x Expr) Expr {
	x = x.Normalize()
	switch x.Kind {
	case KindTrue:
		return False()
	case KindFalse:
		return True()
	case KindNot:
		return x.Children[0]
	default:
		return Expr{Kind: KindNot, Children: []Expr{x}}
	}
}

func (e Expr) Normalize() Expr {
	switch e.Kind {
	case KindAnd:
		return And(e.Children...)
	case KindOr:
		return Or(e.Children...)
	case KindNot:
		if len(e.Children) == 0 {
			return True()
		}
		return Not(e.Children[0])
	default:
		return e
	}
}

func (e Expr) Key() string {
	switch e.Kind {
	case KindTrue, KindFalse:
		return string(e.Kind)
	case KindVar:
		return "var:" + string(e.VarKind) + ":" + e.Name
	case KindNot:
		if len(e.Children) == 0 {
			return "not()"
		}
		return "not(" + e.Children[0].Key() + ")"
	case KindAnd, KindOr:
		parts := make([]string, 0, len(e.Children))
		for _, child := range e.Children {
			parts = append(parts, child.Key())
		}
		return string(e.Kind) + "(" + strings.Join(parts, ",") + ")"
	default:
		return string(e.Kind)
	}
}

func (e Expr) String() string {
	switch e.Kind {
	case KindTrue, KindFalse:
		return string(e.Kind)
	case KindVar:
		return string(e.VarKind) + ":" + e.Name
	case KindNot:
		if len(e.Children) == 0 {
			return "!(true)"
		}
		return "!(" + e.Children[0].String() + ")"
	case KindAnd, KindOr:
		sep := " && "
		if e.Kind == KindOr {
			sep = " || "
		}
		parts := make([]string, 0, len(e.Children))
		for _, child := range e.Children {
			parts = append(parts, child.String())
		}
		return "(" + strings.Join(parts, sep) + ")"
	default:
		return string(e.Kind)
	}
}
