package byteio

import (
	"bytes"
)

// Scanner defines an interface for scanning line-based data
type Scanner interface {
	Scan() bool
	Bytes() []byte
	Error() error
	Position() int
	Length() int
	Seek(int)
	Filename() string
}

// ByteSliceScanner defines a structure for reading lines from a byte slice
type ByteSliceScanner struct {
	beg, end      int
	data, current []byte
	filename      string
}

// NewByteSliceScanner returns a new ByteSliceReader reading from the give input slice
func NewByteSliceScanner(data []byte, filename string) *ByteSliceScanner {
	data = skipBom(data)
	return &ByteSliceScanner{data: data, end: len(data), filename: filename}
}

// Scan scans the current slice for a new line and returns true if one was found
func (r *ByteSliceScanner) Scan() bool {
	if end := bytes.IndexByte(r.data[r.beg:r.end], '\n'); end == -1 {
		r.current = r.data[r.beg:r.end]
		result := r.beg != r.end
		r.beg = r.end
		return result
	} else {
		end += r.beg
		if r.beg != end && r.data[end-1] == '\r' {
			r.current = r.data[r.beg : end-1]
		} else {
			r.current = r.data[r.beg:end]
		}
		r.beg = end + 1
		if r.beg > r.end {
			r.beg = r.end
		}
		return true
	}
}

func (r *ByteSliceScanner) Error() error {
	return nil
}

// Bytes returns the byte slice of the current line
func (r *ByteSliceScanner) Bytes() []byte {
	return r.current
}

func skipBom(data []byte) []byte {
	bom := []byte{0xEF, 0xBB, 0xBF}
	if bytes.HasPrefix(data, bom) {
		data = data[len(bom):]
	}
	return data
}

// CloneBytesSlice clones the input slice
func CloneBytesSlice(input [][]byte) [][]byte {
	result := make([][]byte, 0, len(input))
	length := 0
	for _, s := range input {
		length += len(s)
	}
	data := make([]byte, 0, length)
	for _, s := range input {
		data = append(data, s...)
		result = append(result, data[len(data)-len(s):])
	}
	return result
}

func (r *ByteSliceScanner) Position() int {
	return r.beg
}

func (r *ByteSliceScanner) Length() int {
	return r.beg
}

func (r *ByteSliceScanner) Seek(pos int) {
	if r.beg = pos; r.beg > r.end {
		r.beg = r.end
	} else if r.beg < 0 {
		r.beg = 0
	}
}

func (r *ByteSliceScanner) Filename() string {
	return r.filename
}
