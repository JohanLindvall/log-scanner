package iis

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/JohanLindvall/log-scanner/byteio"
)

var (
	fieldsPrefix = []byte("#Fields: ")
)

// LogEntry holds a parsed log entry
type LogEntry struct {
	Time            time.Time
	SIP             []byte
	CsMethod        []byte
	CsURIStem       []byte
	CsURIQuery      []byte
	SPort           []byte
	CIP             []byte
	CsUsername      []byte
	CsUserAgent     []byte
	CsReferer       []byte
	ScStatus        []byte
	ScSubstatus     []byte
	ScWin32Status   []byte
	TimeTaken       []byte
	Fields, Headers [][]byte
}

// Scanner holds the iis scanning data
type Scanner struct {
	scanner     byteio.Scanner
	headers     [][]byte
	headerIndex []int
	fields      [][]byte
	err         error
	entry       LogEntry
}

// NewScanner returns a new IIS log file scanner
func NewScanner(scanner byteio.Scanner) *Scanner {
	return &Scanner{scanner: scanner}
}

func (s *Scanner) parse() {
	dateField := getData(s.fields, 0)
	timeField := getData(s.fields, 1)
	s.entry.SIP = getData(s.fields, 2)
	s.entry.CsMethod = getData(s.fields, 3)
	s.entry.CsURIStem = getData(s.fields, 4)
	s.entry.CsURIQuery = getData(s.fields, 5)
	s.entry.SPort = getData(s.fields, 6)
	s.entry.CsUsername = getData(s.fields, 7)
	s.entry.CIP = getData(s.fields, 8)
	s.entry.CsUserAgent = getData(s.fields, 9)
	s.entry.CsReferer = getData(s.fields, 10)
	s.entry.ScStatus = getData(s.fields, 11)
	s.entry.ScSubstatus = getData(s.fields, 12)
	s.entry.ScWin32Status = getData(s.fields, 13)
	s.entry.TimeTaken = getData(s.fields, 14)

	if dateField != nil && timeField != nil {
		s.entry.Time, _ = parseDate(dateField, timeField)
	}

	s.entry.Fields = s.fields
	s.entry.Headers = s.fields
}

func getIndex(header []byte, data [][]byte) int {
	for i, v := range data {
		if bytes.Equal(header, v) {
			return i
		}
	}
	return -1
}

func buildIndexArray(headers [][]byte) []int {
	return []int{
		getIndex([]byte("date"), headers),
		getIndex([]byte("time"), headers),
		getIndex([]byte("s-ip"), headers),
		getIndex([]byte("cs-method"), headers),
		getIndex([]byte("cs-uri-stem"), headers),
		getIndex([]byte("cs-uri-query"), headers),
		getIndex([]byte("s-port"), headers),
		getIndex([]byte("cs-username"), headers),
		getIndex([]byte("c-ip"), headers),
		getIndex([]byte("cs(User-Agent)"), headers),
		getIndex([]byte("cs(Referer)"), headers),
		getIndex([]byte("sc-status"), headers),
		getIndex([]byte("sc-substatus"), headers),
		getIndex([]byte("sc-win32-status"), headers),
		getIndex([]byte("time-taken"), headers),
	}
}

func getData(data [][]byte, index int) []byte {
	if index == -1 {
		return nil
	} else {
		return data[index]
	}
}

func parseDate(dateField, timeField []byte) (time.Time, error) {
	var y, m, d, h, mm, s int
	y, dateField = parseInt(dateField)
	dateField = skip(dateField, '-')
	m, dateField = parseInt(dateField)
	dateField = skip(dateField, '-')
	d, dateField = parseInt(dateField)
	h, timeField = parseInt(timeField)
	timeField = skip(timeField, ':')
	mm, timeField = parseInt(timeField)
	timeField = skip(timeField, ':')
	s, timeField = parseInt(timeField)
	if y < 0 || m < 0 || d < 0 || len(dateField) != 0 {
		return time.Time{}, errors.New("bad date")
	}
	if h < 0 || mm < 0 || s < 0 || len(timeField) != 0 {
		return time.Time{}, errors.New("bad time")
	}
	return time.Date(y, time.Month(m), d, h, mm, s, 0, time.UTC), nil
}

func parseInt(input []byte) (int, []byte) {
	result := -1
	offset := 0
	len := len(input)
	for offset < len {
		b := input[offset]
		if b >= '0' && b <= '9' {
			if result == -1 {
				result = 0
			}
			result = result*10 + int(b-'0')
			offset++
		} else {
			break
		}
	}

	return result, input[offset:]
}

func skip(input []byte, val byte) []byte {
	if len(input) > 0 && input[0] == val {
		return input[1:]
	}
	return input
}

// Scan reads the next record from the log
func (s *Scanner) Scan() bool {
	if s.headers == nil {
		for {
			if ok := s.scanner.Scan(); ok {
				line := s.scanner.Bytes()
				if bytes.HasPrefix(line, fieldsPrefix) {
					s.headers = byteio.CloneBytesSlice(bytes.Split(line[len(fieldsPrefix):], []byte(" ")))
					s.headerIndex = buildIndexArray(s.headers)
					break
				}
			} else {
				s.err = s.scanner.Error()
				if s.err == nil {
					s.err = io.EOF
				}
				return ok
			}
		}
	}

	for {
		if ok := s.scanner.Scan(); ok {
			line := s.scanner.Bytes()
			if len(line) > 0 {
				if line[0] == '#' {
					continue
				}
				s.fields = splitInto(line, ' ', s.fields[:0])
				if len(s.fields) != len(s.headers) {
					s.err = errors.New("bad fields data")
					return false
				}
				s.parse()
				return true
			}
		} else {
			s.err = s.scanner.Error()
			return ok
		}
	}
}

// Error returns the scanning errors
func (s *Scanner) Error() error {
	return s.err
}

// Entry returns the log entry
func (s *Scanner) Entry() *LogEntry {
	return &s.entry
}

func splitInto(data []byte, separator byte, destination [][]byte) [][]byte {
	for {
		if i := bytes.IndexByte(data, separator); i == -1 {
			destination = append(destination, data)
			break
		} else {
			destination = append(destination, data[:i])
			data = data[i+1:]
		}
	}

	return destination
}
