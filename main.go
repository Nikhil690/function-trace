package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"tracer/cmd"
)

var bootTime time.Time

const SymbolName = "database/sql.(*DB).QueryRow"

type UserEvent struct {
	Timestamp uint64 // Timestamp
	QueryLen  uint32 // Function parameter (user ID)
	Query     [40]byte
}

type UserReturnEvent struct {
	UserID      int32    // Function parameter (user ID)
	ReturnValue [64]byte // String return value (user name)
	Timestamp   uint64   // Timestamp
}

type Event struct {
	Pid uint32 // int (4)
	Ts  uint32 // int (4)
	Fd  int32  // int (4)
	// _pad  int32   // padding for 8 byte alignment (4)
	Count uint64   // long (8)
	Comm  [16]byte // char[16]
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	path := "./app/test"

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Fatal(err)
	}

	// Load the eBPF program using generated code
	objs := cmd.TracerObjects{}
	if err := cmd.LoadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	// Write the target PID into the filter map

	// Create ring buffer readers
	greetEvents, err := ringbuf.NewReader(objs.GreetParams)
	if err != nil {
		log.Fatal(err)
	}
	defer greetEvents.Close()

	returnEvents, err := ringbuf.NewReader(objs.ReturnParams)
	if err != nil {
		log.Fatal(err)
	}
	defer returnEvents.Close()

	// Process entry events in goroutine
	go func() {
		// callCount := map[int32]uint64{}

		for {
			event, err := greetEvents.Read()
			if err != nil {
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// Cast to UserEvent struct
			userEvent := (*UserEvent)(unsafe.Pointer(&event.RawSample[0]))
			// callCount[userEvent.UserID]++

			secondStr := string(userEvent.Query[:])
			if nullIndex := strings.IndexByte(secondStr, 0); nullIndex != -1 {
				secondStr = secondStr[:nullIndex]
			}
			// Query := extractValidString(userEvent.Query[:])

			log.Printf("[FUNCTION CALL] : Timestamp: %s - QueryRow %s - Query len: %d",
				bootTime.Add(time.Duration(userEvent.Timestamp)).Format(time.RFC3339), secondStr, userEvent.QueryLen)
		}
	}()

	// Process return events in goroutine
	go func() {
		for {
			event, err := returnEvents.Read()
			if err != nil {
				log.Printf("Error reading from return ring buffer: %v", err)
				continue
			}

			// Cast to UserReturnEvent struct
			returnEvent := (*UserReturnEvent)(unsafe.Pointer(&event.RawSample[0]))

			// Convert byte array to string, stopping at null terminator
			returnStr := string(returnEvent.ReturnValue[:])
			if nullIndex := strings.IndexByte(returnStr, 0); nullIndex != -1 {
				returnStr = returnStr[:nullIndex]
			}

			log.Printf("[FUNCTION RETURN] getUserByID returned: '%s' - Timestamp: %d",
				returnStr, returnEvent.Timestamp)
		}
	}()

	uprobeLink, err := ex.Uprobe(SymbolName, objs.GoTest, &link.UprobeOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer uprobeLink.Close()

	// Attach uretprobe using the generated program objects
	// uretprobeLink, err := ex.Uretprobe(SymbolName, objs.GoTestReturn, &link.UprobeOptions{})
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer uretprobeLink.Close()

	log.Printf("✅ Successfully attached eBPF tracer to %s", SymbolName)
	log.Printf("🔍 Monitoring getUserByID function calls...")
	log.Printf("📡 Test by making requests to: http://localhost:8085/user/")
	log.Printf("🛑 Press Ctrl+C to exit")

	// Keep the program running
	for {
		time.Sleep(time.Second)
	}
}

func extractValidString(data []byte) string {
	var validBytes []byte
	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII characters
			validBytes = append(validBytes, b)
		} else {
			break // Stop at first non-printable character
		}
	}
	return string(validBytes)
}

func init() {
	// Read uptime from /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		panic(err)
	}
	parts := strings.Fields(string(data))
	uptimeSec, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		panic(err)
	}

	now := time.Now()
	bootTime = now.Add(-time.Duration(uptimeSec * float64(time.Second)))
}
