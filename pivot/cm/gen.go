// tracer/gen.go
package cm

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-g -O2" -target bpfel Tracer ../bpf/bpf.c -- -I./bpf/.
