package generic

import (
	"regexp"
	"strings"
	"time"
)

// 2019-06-22 19:34:13,510 [26] ERROR
var log4netre = regexp.MustCompile("^([12][0-9]{3}-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-9]{2}(,[0-9]+)?)\\s(\\[([^]]+)\\]\\s)?([A-Z]+)\\s+(.*)$")

type log4net struct {
	entry   [2]LogEntry
	current int
}

func newlog4net(s *Scanner) consumer {
	return &log4net{current: -1}
}

func (c *log4net) consume(line []byte) (entry *LogEntry, err error) {
	if match := log4netre.FindSubmatch(line); match != nil {
		if c.current != -1 {
			entry = &c.entry[c.current]
		}
		if c.current == 0 {
			c.current = 1
		} else {
			c.current = 0
		}
		dest := &c.entry[c.current]
		dest.Thread = match[4]
		dest.Level = match[5]
		dest.Message = append(dest.Message[:0], match[6])
		dest.Time, err = time.Parse("2006-01-02 15:04:05.999", strings.ReplaceAll(string(match[1]), ",", "."))
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

func (c *log4net) flush() (entry *LogEntry) {
	if c.current != -1 {
		entry = &c.entry[c.current]
		c.current = -1
	}
	return
}
