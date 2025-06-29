package main

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	// "unsafe"

	// "github.com/cilium/ebpf"
	// "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	// Import the package containing your generated eBPF code
	"pivot/cm"
)

type FuncEvent struct {
	Tid       uint32        `json:"tid"`
	Name      string        `json:"name"`
	Duration  time.Duration `json:"duration"`
	StartTime time.Time     `json:"start_time"`
}

type Span struct {
	SpanID      string      `json:"span_id"`
	HTTPRequest string      `json:"http_request"`
	StartTime   time.Time   `json:"start_time"`
	Events      []FuncEvent `json:"events"`
}

func main() {
	// Remove resource limits
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load eBPF program
	objs := cm.TracerObjects{}
	if err := cm.LoadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Get executable path
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}

	// Build symbol table
	symTable, err := createSymbolTable(exePath)
	if err != nil {
		log.Fatal(err)
	}

	// Attach probes
	if err := attachProbes(&objs, exePath, symTable); err != nil {
		log.Fatal(err)
	}

	// Process events
	processEvents(&objs, symTable)
}

func createSymbolTable(exePath string) (*gosym.Table, error) {
    // Read the executable file
    exeData, err := os.ReadFile(exePath)
    if err != nil {
        return nil, fmt.Errorf("reading executable: %w", err)
    }

    // Find the .gopclntab section
    pcln := gosym.NewLineTable(exeData, 0)
    if pcln == nil {
        return nil, errors.New("could not create line table")
    }

    // Create symbol table
    tab, err := gosym.NewTable(nil, pcln)
    if err != nil {
        return nil, fmt.Errorf("creating symbol table: %w", err)
    }

    return tab, nil
}

func attachProbes(objs *cm.TracerObjects, exePath string, symTable *gosym.Table) error {
	// Attach to all main.* functions
	path := "../app/test" 
	funcs, err := findMainFunctions(path)
	ef, err := elf.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer ef.Close()

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		return err
	}

	for _, fn := range funcs {
		// Entry probe
		up, err := ex.Uprobe(fn, objs.GenericFuncEntry, &link.UprobeOptions{})
		if err != nil {
			log.Printf("Skipping %s: %v", fn, err)
			continue
		}
		defer up.Close()

		// Exit probe
		upRet, err := ex.Uretprobe(fn, objs.GenericFuncExit, &link.UprobeOptions{})
		if err != nil {
			log.Printf("Skipping retprobe for %s: %v", fn, err)
			continue
		}
		defer upRet.Close()
	}

	// Attach HTTP handler
	if err := attachHTTPProbes(objs, ex); err != nil {
		return err
	}

	log.Printf("Attached %d probes to %s", len(funcs), exePath)
	return nil
}

func findMainFunctions(exePath string) ([]string, error) {
	cmd := exec.Command("go", "tool", "nm", exePath)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var funcs []string
	re := regexp.MustCompile(` T main\.\w+`)
	lines := bytes.Split(out, []byte{'\n'})

	for _, line := range lines {
		if re.Match(line) {
			parts := bytes.Split(line, []byte{' '})
			if len(parts) > 2 {
				name := string(parts[len(parts)-1])
				funcs = append(funcs, name)
			}
		}
	}
	return funcs, nil
}

func attachHTTPProbes(objs *cm.TracerObjects, exePath *link.Executable) error {
	// HTTP entry
	up, err := exePath.Uprobe("net/http.(*ServeMux).ServeHTTP", objs.HttpEntry, nil)
	if err != nil {
		return fmt.Errorf("HTTP entry probe: %w", err)
	}
	defer up.Close()
	return nil
}

func processEvents(objs *cm.TracerObjects, symTable *gosym.Table) {
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	spans := make(map[uint32]*Span)

	log.Println("Listening for events... Press Ctrl-C to exit")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading event: %v", err)
			continue
		}

		if len(record.RawSample) < 4 {
			continue
		}

		// First 4 bytes are always TID
		tid := binary.LittleEndian.Uint32(record.RawSample[0:4])

		switch len(record.RawSample) {
		case 12: // span_start
			ts := binary.LittleEndian.Uint64(record.RawSample[4:12])
			spans[tid] = &Span{
				SpanID:    generateSpanID(),
				StartTime: time.Unix(0, int64(ts)),
				Events:    []FuncEvent{},
			}

			// Get HTTP payload
			var payload [256]byte
			if err := objs.HttpMap.Lookup(tid, &payload); err == nil {
				spans[tid].HTTPRequest = strings.TrimRight(string(payload[:]), "\x00")
			}

			log.Printf("New span started: TID=%d, ID=%s", tid, spans[tid].SpanID)

		case 32: // func_event
			startTs := binary.LittleEndian.Uint64(record.RawSample[4:12])
			endTs := binary.LittleEndian.Uint64(record.RawSample[12:20])
			funcAddr := binary.LittleEndian.Uint64(record.RawSample[20:28])

			if span, exists := spans[tid]; exists {
				name := resolveFunctionName(symTable, funcAddr)
				event := FuncEvent{
					Tid:       tid,
					Name:      name,
					Duration:  time.Duration(endTs - startTs),
					StartTime: time.Unix(0, int64(startTs)),
				}
				span.Events = append(span.Events, event)
				log.Printf("Function event: TID=%d, Func=%s, Duration=%s",
					tid, name, event.Duration)
			}

		case 4: // span_end
			if span, exists := spans[tid]; exists {
				jsonData, _ := json.Marshal(span)
				fmt.Println(string(jsonData))
				delete(spans, tid)
				objs.HttpMap.Delete(tid)
				log.Printf("Span completed: TID=%d, ID=%s", tid, span.SpanID)
			}
		}
	}
}

func resolveFunctionName(symTable *gosym.Table, addr uint64) string {
	// Adjust for ASLR - get base address
	base := getBaseAddress()

	// Calculate actual function address
	actualAddr := addr - base

	// Look up function
	if fn := symTable.PCToFunc(actualAddr); fn != nil {
		return fn.Name
	}
	return fmt.Sprintf("unknown@%x", addr)
}

func getBaseAddress() uint64 {
	// On Linux, we can get the base address from /proc/self/maps
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/self/maps")
		if err != nil {
			return 0
		}

		lines := bytes.Split(data, []byte{'\n'})
		for _, line := range lines {
			if bytes.Contains(line, []byte("r-xp")) && bytes.Contains(line, []byte("main")) {
				parts := bytes.SplitN(line, []byte{'-'}, 2)
				if len(parts) > 0 {
					addr, err := parseHexUint64(string(parts[0]))
					if err == nil {
						return addr
					}
				}
			}
		}
	}
	return 0
}

func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return 0, nil
	}
	var n uint64
	_, err := fmt.Sscanf(s, "%x", &n)
	return n, err
}

func generateSpanID() string {
	// In production, use crypto/rand
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
