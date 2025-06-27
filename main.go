package main

import (
    "debug/elf"
    "log"
    "unsafe"
    "time"
    "strings"
    
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"

	"tracer/cmd"
)

const SymbolName = "main.getUserByID"

type UserEvent struct {
    UserID    int32  // Function parameter (user ID)
    Timestamp uint64 // Timestamp
}

type UserReturnEvent struct {
    ReturnValue [64]byte // String return value
    Timestamp   uint64   // Timestamp
}

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }
    
    path := "./app/test"
    
    // Open in elf format in order to get the symbols
    ef, err := elf.Open(path)
    if err != nil {
        log.Fatal(err)
    }
    defer ef.Close()
    
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
        countMap := map[int32]uint64{}
        
        for {
            event, err := greetEvents.Read()
            if err != nil {
                log.Printf("Error reading from ring buffer: %v", err)
                continue
            }
            
            // Cast to UserEvent struct
            userEvent := (*UserEvent)(unsafe.Pointer(&event.RawSample[0]))
            countMap[userEvent.UserID]++
            
            log.Printf("[ENTRY] User ID: %d, Count: %d, Timestamp: %d", 
                userEvent.UserID, countMap[userEvent.UserID], userEvent.Timestamp)
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
            
            log.Printf("[RETURN] Return Value: %s, Timestamp: %d", 
                returnStr, returnEvent.Timestamp)
        }
    }()
    
    // Attach uprobe using the generated program objects
    uprobeLink, err := ex.Uprobe(SymbolName, objs.GoTest, &link.UprobeOptions{})
    if err != nil {
        log.Fatal(err)
    }
    defer uprobeLink.Close()
    
    // Attach uretprobe using the generated program objects
    uretprobeLink, err := ex.Uretprobe(SymbolName, objs.GoTestReturn, &link.UprobeOptions{})
    if err != nil {
        log.Fatal(err)
    }
    defer uretprobeLink.Close()
    
    log.Printf("Successfully attached to %s. Press Ctrl+C to exit.", SymbolName)
    
    // Keep the program running
    for {
        time.Sleep(time.Second)
    }
}