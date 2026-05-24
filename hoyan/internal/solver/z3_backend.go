//go:build z3

package solver

/*
#cgo LDFLAGS: -lz3
#include <stdlib.h>
#include <z3.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Z3Backend struct{}

func (Z3Backend) Solve(problem FailureProblem) (Answer, error) {
	cfg := C.Z3_mk_config()
	defer C.Z3_del_config(cfg)
	ctx := C.Z3_mk_context(cfg)
	defer C.Z3_del_context(ctx)
	solver := C.Z3_mk_solver(ctx)
	C.Z3_solver_inc_ref(ctx, solver)
	defer C.Z3_solver_dec_ref(ctx, solver)

	vars := map[string]C.Z3_ast{}
	for _, name := range problem.Links {
		vars[name] = boolConst(ctx, name)
	}
	if problem.MaxFailures >= 0 {
		C.Z3_solver_assert(ctx, solver, atMost(ctx, vars, problem.Links, problem.MaxFailures))
	}
	if len(problem.Forbidden) == 0 {
		C.Z3_solver_assert(ctx, solver, C.Z3_mk_false(ctx))
	} else {
		var clauses []C.Z3_ast
		for _, clause := range problem.Forbidden {
			var lits []C.Z3_ast
			for _, name := range clause {
				lits = append(lits, vars[name])
			}
			clauses = append(clauses, mkAnd(ctx, lits))
		}
		C.Z3_solver_assert(ctx, solver, mkOr(ctx, clauses))
	}
	switch C.Z3_solver_check(ctx, solver) {
	case C.Z3_L_TRUE:
		model := C.Z3_solver_get_model(ctx, solver)
		C.Z3_model_inc_ref(ctx, model)
		defer C.Z3_model_dec_ref(ctx, model)
		var failed []string
		for _, name := range problem.Links {
			var value C.Z3_ast
			ok := C.Z3_model_eval(ctx, model, vars[name], C.bool(true), &value)
			if !bool(ok) {
				continue
			}
			if C.Z3_get_bool_value(ctx, value) == C.Z3_L_TRUE {
				failed = append(failed, name)
			}
		}
		return Answer{Sat: true, Failures: failed, Backend: "z3"}, nil
	case C.Z3_L_FALSE:
		return Answer{Sat: false, Backend: "z3"}, nil
	default:
		return Answer{Sat: false, Backend: "z3"}, fmt.Errorf("z3 returned unknown")
	}
}

func boolConst(ctx C.Z3_context, name string) C.Z3_ast {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	sym := C.Z3_mk_string_symbol(ctx, cname)
	return C.Z3_mk_const(ctx, sym, C.Z3_mk_bool_sort(ctx))
}

func atMost(ctx C.Z3_context, vars map[string]C.Z3_ast, names []string, max int) C.Z3_ast {
	var terms []C.Z3_ast
	for _, name := range names {
		one := C.Z3_mk_int(ctx, 1, C.Z3_mk_int_sort(ctx))
		zero := C.Z3_mk_int(ctx, 0, C.Z3_mk_int_sort(ctx))
		terms = append(terms, C.Z3_mk_ite(ctx, vars[name], one, zero))
	}
	sum := mkAdd(ctx, terms)
	limit := C.Z3_mk_int(ctx, C.int(max), C.Z3_mk_int_sort(ctx))
	return C.Z3_mk_le(ctx, sum, limit)
}

func mkAnd(ctx C.Z3_context, xs []C.Z3_ast) C.Z3_ast {
	if len(xs) == 0 {
		return C.Z3_mk_true(ctx)
	}
	return C.Z3_mk_and(ctx, C.uint(len(xs)), (*C.Z3_ast)(unsafe.Pointer(&xs[0])))
}

func mkOr(ctx C.Z3_context, xs []C.Z3_ast) C.Z3_ast {
	if len(xs) == 0 {
		return C.Z3_mk_false(ctx)
	}
	return C.Z3_mk_or(ctx, C.uint(len(xs)), (*C.Z3_ast)(unsafe.Pointer(&xs[0])))
}

func mkAdd(ctx C.Z3_context, xs []C.Z3_ast) C.Z3_ast {
	if len(xs) == 0 {
		return C.Z3_mk_int(ctx, 0, C.Z3_mk_int_sort(ctx))
	}
	return C.Z3_mk_add(ctx, C.uint(len(xs)), (*C.Z3_ast)(unsafe.Pointer(&xs[0])))
}
