package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/DECK36/go-gelf/gelf"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

/*
	http://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
	https://github.com/Graylog2/graylog2-docs/wiki/GELF
*/
type SystemdJournalEntry struct {
	Cursor                    string `json:"__CURSOR"`
	Realtime_timestamp        int64  `json:"__REALTIME_TIMESTAMP,string"`
	Monotonic_timestamp       string `json:"__MONOTONIC_TIMESTAMP"`
	Boot_id                   string `json:"_BOOT_ID"`
	Transport                 string `json:"_TRANSPORT"`
	Priority                  int32  `json:"PRIORITY,string"`
	Syslog_facility           string `json:"SYSLOG_FACILITY"`
	Syslog_identifier         string `json:"SYSLOG_IDENTIFIER"`
	Message                   string `json:"MESSAGE"`
	Pid                       string `json:"_PID"`
	Uid                       string `json:"_UID"`
	Gid                       string `json:"_GID"`
	Comm                      string `json:"_COMM"`
	Exe                       string `json:"_EXE"`
	Cmdline                   string `json:"_CMDLINE"`
	Systemd_cgroup            string `json:"_SYSTEMD_CGROUP"`
	Systemd_session           string `json:"_SYSTEMD_SESSION"`
	Systemd_owner_uid         string `json:"_SYSTEMD_OWNER_UID"`
	Systemd_unit              string `json:"_SYSTEMD_UNIT"`
	Source_realtime_timestamp string `json:"_SOURCE_REALTIME_TIMESTAMP"`
	Machine_id                string `json:"_MACHINE_ID"`
	Hostname                  string `json:"_HOSTNAME"`
	FullMessage               string
}

// Strip date from message-content. Use named subpatterns to override other fields
var messageReplace = map[*regexp.Regexp]string{
	regexp.MustCompile("^20[0-9][0-9]/[01][0-9]/[0123][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \\[(?P<Priority>[a-z]+)\\] "):            "", //nginx
	regexp.MustCompile("^20[0-9][0-9]-[01][0-9]-[0123][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9],[0-9]{3} (?P<Priority>[A-Z]+) : "):       "", //graylog2-server
	regexp.MustCompile("^[0-9]{6} [0-1]?[0-9]:[0-5][0-9]:[0-5][0-9] \\[(?P<Priority>[A-Z]+)\\] "):                                     "", //mysqld
	regexp.MustCompile("^\\[([A-Z][a-z][a-] ){2} [0-9]+ [0-2][0-9]:[0-5][0-9]:[0-5][0-9]\\.[0-9]{3} 20[0-9][0-9]\\] \\[ [0-9]+ \\] "): "", //sphinx
	regexp.MustCompile("^[A-Z][a-z]{2} [01][0-9], 20[0-9][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] [AP]M "):                              "", //jenkins
	regexp.MustCompile("^pool [a-z]+: "):                                                                                              "", //php-fpm
}

var priorities = map[string]int32{
	"emergency": 0,
	"emerg":     0,
	"alert":     1,
	"critical":  2,
	"crit":      2,
	"error":     3,
	"err":       3,
	"warning":   4,
	"warn":      4,
	"notice":    5,
	"info":      6,
	"debug":     7,
}

func (this *SystemdJournalEntry) toGelf() *gelf.Message {
	var extra = map[string]interface{}{
		"Boot_id": this.Boot_id,
		"Pid":     this.Pid,
		"Uid":     this.Uid,
	}

	// php-fpm refuses to fill identifier
	facility := this.Syslog_identifier
	if "" == facility {
		facility = this.Comm
	}

	if this.isJsonMessage() {
		if err := json.Unmarshal([]byte(this.Message), &extra); err == nil {
			if m, ok := extra["Message"]; ok {
				this.Message = m.(string)
				delete(extra, "Message")
			}

			if f, ok := extra["FullMessage"]; ok {
				this.FullMessage = f.(string)
				delete(extra, "FullMessage")
			}
		}
	} else if -1 != strings.Index(this.Message, "\n") {
		this.FullMessage = this.Message
		this.Message = strings.Split(this.Message, "\n")[0]
	}

	return &gelf.Message{
		Version:  "1.1",
		Host:     this.Hostname,
		Short:    this.Message,
		Full:     this.FullMessage,
		TimeUnix: float64(this.Realtime_timestamp) / 1000 / 1000,
		Level:    this.Priority,
		Facility: facility,
		Extra:    extra,
	}
}

func (this *SystemdJournalEntry) process() {
	for re, replace := range messageReplace {
		m := re.FindStringSubmatch(this.Message)
		if m == nil {
			continue
		}

		// Store subpatterns in fields
		for idx, key := range re.SubexpNames() {
			if "Priority" == key {
				this.Priority = priorities[strings.ToLower(m[idx])]
			}
		}

		this.Message = re.ReplaceAllString(this.Message, replace)

		// We won't match multiple replaces
		break
	}
}

func (this *SystemdJournalEntry) sameSource(message *SystemdJournalEntry) bool {
	if this.Syslog_identifier != message.Syslog_identifier {
		return false
	}

	if this.Priority != message.Priority {
		return false
	}

	if this.Realtime_timestamp-message.Realtime_timestamp > SAMESOURCE_TIME_DIFFERENCE {
		return false
	}

	return true
}

func (this *SystemdJournalEntry) send() {
	message := this.toGelf()

	if err := writer.WriteMessage(message); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func (this *SystemdJournalEntry) isJsonMessage() bool {
	return len(this.Message) > 64 && this.Message[0] == '{' && this.Message[1] == '"'
}

func (this *SystemdJournalEntry) extendWith(message *SystemdJournalEntry) {
	if this.FullMessage == "" {
		this.FullMessage = this.Message
	}

	this.FullMessage += "\n" + message.Message
}

var (
	pendingEntry *SystemdJournalEntry
	writer       *gelf.Writer
)

const (
	WRITE_INTERVAL             = 50 * time.Millisecond
	SAMESOURCE_TIME_DIFFERENCE = 100 * 1000
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Pass server:12201 as first argument and append journalctl parameters to use")
		os.Exit(1)
	}

	if w, err := gelf.NewWriter(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "While connecting to Graylog server: %s\n", err)
		os.Exit(1)
	} else {
		writer = w
	}

	journalArgs := []string{"--all", "--output=json"}
	journalArgs = append(journalArgs, os.Args[2:]...)
	cmd := exec.Command("journalctl", journalArgs...)

	stderr, _ := cmd.StderrPipe()
	go io.Copy(os.Stderr, stderr)
	stdout, _ := cmd.StdoutPipe()
	s := bufio.NewScanner(stdout)

	go writePendingEntry()

	cmd.Start()

	for s.Scan() {
		line := s.Text()

		var entry = &SystemdJournalEntry{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			//fmt.Fprintf(os.Stderr, "Could not parse line, skipping: %s\n", line)
			continue
		}

		entry.process()

		if pendingEntry == nil {
			pendingEntry = entry
		} else if !pendingEntry.sameSource(entry) || pendingEntry.isJsonMessage() {
			pendingEntry.send()
			pendingEntry = entry
		} else {
			pendingEntry.extendWith(entry)

			// Keeps writePendingEntry waiting longer for us to append even more
			pendingEntry.Realtime_timestamp = entry.Realtime_timestamp
		}

		// Prevent saturation and throttling
		time.Sleep(1 * time.Millisecond)
	}

	if err := s.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error from journalctl: %s\n", err)
	}

	cmd.Wait()
	pendingEntry.send()
}

func writePendingEntry() {
	var entry *SystemdJournalEntry

	for {
		time.Sleep(WRITE_INTERVAL)

		if pendingEntry != nil && (time.Now().UnixNano()/1000-pendingEntry.Realtime_timestamp) > SAMESOURCE_TIME_DIFFERENCE {
			entry = pendingEntry
			pendingEntry = nil

			entry.send()
		}
	}
}