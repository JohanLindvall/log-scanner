package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"

	"github.com/JohanLindvall/log-scanner/byteio"
	"github.com/JohanLindvall/log-scanner/generic"
	"github.com/JohanLindvall/log-scanner/iis"
	"github.com/JohanLindvall/mmap-go"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	file, err := os.Open(flag.Args()[0])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	m, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		panic(err)
	}
	defer m.Unmap()
	data := []byte(m)
	rdr := byteio.NewByteSliceScanner(data, file.Name())
	lc := 0

	if false {
		for log := iis.NewScanner(rdr); log.Scan(); {
			entry := log.Entry()
			sc, _ := strconv.Atoi(string(entry.ScStatus))
			if sc != 302 && sc != 304 && (sc < 200 || sc > 299) {
				fmt.Printf("%v %s %s %s %d\n", entry.Time, string(entry.CsMethod), string(entry.CsURIStem), string(entry.CsURIQuery), sc)
			}
		}
	}

	for log := generic.NewScanner(rdr); log.Scan(); {
		entry := log.Entry()
		for range entry.Message {
			lc++
		}
	}

	fmt.Println(lc)

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		runtime.GC()    // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
}
