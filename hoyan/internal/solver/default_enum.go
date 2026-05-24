//go:build !z3

package solver

func DefaultBackend() Backend {
	return EnumeratingBackend{}
}
