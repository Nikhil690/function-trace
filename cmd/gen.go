// tracer/gen.go
package cmd

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-g -O2" -target bpfel -output-dir ./bpf Tracer ./bpf/bpf.c -- -I./bpf/.