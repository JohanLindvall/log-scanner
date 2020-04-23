package generic

import (
	"regexp"
	"time"
)

// 03:00:28 [Debug] [USER] [Machine] [Source.Levels] message
var nlogre = regexp.MustCompile("^([0-2][0-9]:[0-5][0-9]:[0-5][0-9])\\s\\[([^]]+)\\]\\s\\[([^]]+)\\]\\s\\[([^]]+)\\]\\s\\[([^]]+)\\]\\s+(.*)$")

type nlog struct {
	entry   [2]LogEntry
	current int
	meta []byte
}

func newnlog(s *Scanner) consumer {
	return &nlog{current: -1, meta: []byte("2010-01-01 ")}
}

func (c *nlog) consume(line []byte) (entry *LogEntry, err error) {
	if match := nlogre.FindSubmatch(line); match != nil {
		if c.current != -1 {
			entry = &c.entry[c.current]
		}
		if c.current == 0 {
			c.current = 1
		} else {
			c.current = 0
		}
		dest := &c.entry[c.current]

		dest.Level = match[2]
		dest.User = match[3]
		dest.Machine = match[4]
		dest.Source = match[5]
		dest.Message = append(dest.Message, match[6])
		dest.Time, err = time.Parse("2006-01-02 15:04:05", string(c.meta)+string(match[1]))
	} else {
		if c.current == -1 {
			err = UnknownData
		} else {
			dest := &c.entry[c.current]
			dest.Message = append(dest.Message, line)
		}
	}

	return
}

func (c *nlog) flush() (entry *LogEntry) {
	if c.current != -1 {
		entry = &c.entry[c.current]
		c.current = -1
	}
	return
}
