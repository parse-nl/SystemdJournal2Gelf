package main

import (
	"bufio"
	"encoding/json"
	"github.com/SocialCodeInc/go-gelf/gelf"
	"io"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"regexp"
)

/*
	http://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
	https://github.com/Graylog2/graylog2-docs/wiki/GELF
*/
type SystemdJournalEntry struct {
	Cursor						string `json:"__CURSOR"`
	Realtime_timestamp			int64  `json:"__REALTIME_TIMESTAMP,string"`
	Monotonic_timestamp			string `json:"__MONOTONIC_TIMESTAMP"`
	Boot_id						string `json:"_BOOT_ID"`
	Transport					string `json:"_TRANSPORT"`
	Priority					int32  `json:"PRIORITY,string"`
	Syslog_facility				string `json:"SYSLOG_FACILITY"`
	Syslog_identifier			string `json:"SYSLOG_IDENTIFIER"`
	Message						string `json:"MESSAGE"`
	Pid							string `json:"_PID"`
	Uid							string `json:"_UID"`
	Gid							string `json:"_GID"`
	Comm						string `json:"_COMM"`
	Exe							string `json:"_EXE"`
	Cmdline						string `json:"_CMDLINE"`
	Systemd_cgroup				string `json:"_SYSTEMD_CGROUP"`
	Systemd_session				string `json:"_SYSTEMD_SESSION"`
	Systemd_owner_uid			string `json:"_SYSTEMD_OWNER_UID"`
	Systemd_unit				string `json:"_SYSTEMD_UNIT"`
	Source_realtime_timestamp	string `json:"_SOURCE_REALTIME_TIMESTAMP"`
	Machine_id					string `json:"_MACHINE_ID"`
	Hostname					string `json:"_HOSTNAME"`
	FullMessage					string
}

// Use named subpatterns to override other fields
var messageReplace = map[*regexp.Regexp]string{
	regexp.MustCompile("^20[0-9][0-9]/[01][0-9]/[0123][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \\[(?P<Priority>[a-z]+)\\] "): "", //nginx
	regexp.MustCompile("^20[0-9][0-9]-[01][0-9]-[0123][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9],[0-9]{3} (?P<Priority>[A-Z]+): "): "", //graylog2-server
	regexp.MustCompile("^[0-9]{6} [0-1]?[0-9]:[0-5][0-9]:[0-5][0-9] \\[(?P<Priority>[A-Z]+)\\] "): "", //mysqld
	regexp.MustCompile("^\\[([A-Z][a-z][a-] ){2} [0-9]+ [0-2][0-9]:[0-5][0-9]:[0-5][0-9]\\.[0-9]{3} 20[0-9][0-9]\\] \\[ [0-9]+ \\] "): "", //sphinx
}

var priorities = map[string]int32{
	"emergency":0,
	"emerg":	0,
	"alert":	1,
	"critical":	2,
	"crit":		2,
	"error":	3,
	"err":		3,
	"warning":	4,
	"warn":		4,
	"notice":	5,
	"info":		6,
	"debug":	7,
}

func (this *SystemdJournalEntry) toGelf() (*gelf.Message) {
	if -1 != strings.Index(this.Message, "\n") {
		this.FullMessage = this.Message
		this.Message = strings.Split(this.Message, "\n")[0]
	}

	// php-fpm refuses to fill identifier
	facility := this.Syslog_identifier
	if "" == facility {
		facility = this.Comm
	}

	return &gelf.Message{
		Version:	"1.0",
		Host:		this.Hostname,
		Short:		this.Message,
		Full:		this.FullMessage,
		TimeUnix:	this.Realtime_timestamp / 1000 / 1000,
		Level:		this.Priority,
		Facility:	facility,
		Extra:		map[string]interface{}{
			"Boot_id":	this.Boot_id,
			"Pid":		this.Pid,
			"Uid":		this.Uid,
		},
	}
}

func (this *SystemdJournalEntry) process() {
	for re, replace := range messageReplace {
		m := re.FindStringSubmatch(this.Message)
		if nil == m {
			continue
		}

		for idx, key := range re.SubexpNames() {
			// no need for reflect, just define desired keys here
			if "Priority" == key {
				this.Priority = priorities[strings.ToLower(m[idx])]
			}
		}

		this.Message = re.ReplaceAllString(this.Message, replace)
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

	if err := gelfWriter.WriteMessage(message); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func (this *SystemdJournalEntry) extendWith(message *SystemdJournalEntry) {
	if this.FullMessage == "" {
		this.FullMessage = this.Message
	}

	this.FullMessage += "\n" + message.Message
}

var (
	pendingEntry *SystemdJournalEntry
	gelfWriter   *gelf.Writer
)

const (
	WRITE_INTERVAL = 50 * time.Millisecond
	SAMESOURCE_TIME_DIFFERENCE = 100*1000
	JOURNAL_READER_BUFFER = 16384
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Pass server:12201 as first argument and append journalctl parameters to use")
		os.Exit(1)
	}

	serverAddr := os.Args[1]
	journalArgs := []string{"--all", "--output=json"}
	journalArgs = append(journalArgs, os.Args[2:]...)
	cmd := exec.Command("journalctl", journalArgs...)

	var err error
	gelfWriter, err = gelf.NewWriter(serverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "While connecting to Graylog server: %s\n", err)
		os.Exit(1)
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go io.Copy(os.Stderr, stderr)

	go writePendingEntry()

	// Larger buffer for systemd's inline coredumps which are typically ~ 14Kb
	r := bufio.NewReaderSize(stdout, JOURNAL_READER_BUFFER)
	cmd.Start()

	for line, _, err := r.ReadLine(); err != io.EOF; line, _, err = r.ReadLine() {
		if err != nil {
			break
		}

		entry := new(SystemdJournalEntry)

		if err = json.Unmarshal(line, &entry); err != nil {
//			fmt.Fprintf(os.Stderr, "Could not parse line, skipping: %s\n", line)
			continue
		}

		entry.process()

		if pendingEntry == nil {
			pendingEntry = entry
		} else if !pendingEntry.sameSource(entry) {
			go pendingEntry.send()
			pendingEntry = entry
		} else {
			pendingEntry.extendWith(entry)

			// Keeps writePendingEntry waiting longer for us to append even more
			pendingEntry.Realtime_timestamp = entry.Realtime_timestamp
		}

		// Prevent saturation and throttling
		time.Sleep(1 * time.Millisecond)
	}

	cmd.Wait()
}

/*
 * Sleep for WritePending_interval, then check if
*/
func writePendingEntry() {
	for {
		time.Sleep(WRITE_INTERVAL)

		if pendingEntry != nil && (time.Now().UnixNano() / 1000 - pendingEntry.Realtime_timestamp) > SAMESOURCE_TIME_DIFFERENCE {
			go pendingEntry.send()
			pendingEntry = nil
		}
	}
}
