package generic

import (
	"errors"
	"time"

	"github.com/JohanLindvall/log-scanner/byteio"
)

// LogEntry holds a parsed log entry
type LogEntry struct {
	Time    time.Time
	Thread  []byte
	Level   []byte
	Machine []byte
	Source  []byte
	User    []byte
	Message [][]byte
}

type consumer interface {
	consume([]byte) (entry *LogEntry, err error)
	flush() (entry *LogEntry)
}

// Scanner holds the scanning data
type Scanner struct {
	scanner   byteio.Scanner
	err       error
	current   consumer
	consumers []consumer
	entry     *LogEntry
}

var (
	UnknownData   = errors.New("unknown data")
	AmbigiousData = errors.New("ambigouos data")
)

// NewScanner returns a new generic scanner
func NewScanner(scanner byteio.Scanner) (result *Scanner) {
	result = &Scanner{scanner: scanner}
	result.consumers = []consumer{
		newlog4net(result),
		newnlog(result),
	}

	return
}

// Scan reads the next record from the log
func (s *Scanner) Scan() bool {
	for s.scanner.Scan() {
		line := s.scanner.Bytes()
		if s.current == nil {
			for _, c := range s.consumers {
				if entry, err := c.consume(line); err == nil {
					if s.current != nil {
						s.err = AmbigiousData
						return false
					}
					s.current = c
					if entry != nil {
						s.entry = entry
					}
				} else if err != UnknownData {
					s.err = err
					return false
				}
			}
			if s.entry != nil {
				return true
			}
		} else {
			if entry, err := s.current.consume(line); err == nil {
				if entry != nil {
					s.entry = entry
					return true
				}
			} else if err != nil {
				s.err = err
				return false
			}
		}
	}

	if s.current != nil {
		if entry := s.current.flush(); entry != nil {
			s.entry = entry
			return true
		}
	}

	return false
}

// Error returns the scanning errors
func (s *Scanner) Error() error {
	return s.err
}

// Entry returns the parsed entry
func (s *Scanner) Entry() *LogEntry {
	return s.entry
}
