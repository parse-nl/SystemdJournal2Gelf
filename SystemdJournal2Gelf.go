package main

import (
	"bufio"
	"encoding/json"
	"github.com/SocialCodeInc/go-gelf/gelf"
	"io"
	"log"
	"os"
	"os/exec"
	"time"
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

func (this *SystemdJournalEntry) toGelf() (*gelf.Message, error) {
	return &gelf.Message{
		Version: 	"1.0",
		Host:		this.Hostname,
		Short:		this.Message,
		Full:		this.FullMessage,
		TimeUnix:	this.Realtime_timestamp / 1000 / 1000,
		Level:		this.Priority,
		Facility:	this.Syslog_identifier,
		Extra: map[string]interface{}{
			"Boot_id":	this.Boot_id,
			"Pid":		this.Pid,
			"Uid":		this.Uid,
		},
	}, nil
}

func (this *SystemdJournalEntry) sameSource(message *SystemdJournalEntry) bool {
	if this.Syslog_identifier != message.Syslog_identifier {
		return false
	}

	if this.Priority != message.Priority {
		return false
	}

	// less than 1 second in between
	if this.Realtime_timestamp-message.Realtime_timestamp > 1000000 {
		return false
	}

	return true
}

func (this *SystemdJournalEntry) send() {
	if message, err := this.toGelf(); err != nil {
		log.Print(err)
	} else {
		go gelfWriter.WriteMessage(message)
		pendingEntry = nil
	}
}

var (
	pendingEntry *SystemdJournalEntry
	gelfWriter   *gelf.Writer
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("Pass server:12201 as first argument and append journalctl parameters to use")
	}

	serverAddr := os.Args[1]
	journalArgs := os.Args[1:]
	journalArgs[0] = "--output=json"

	cmd := exec.Command("journalctl", journalArgs...)

	var err error
	gelfWriter, err = gelf.NewWriter(serverAddr)
	if err != nil {
		log.Fatalf("While connecting to Graylog server: %s", err)
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go io.Copy(os.Stderr, stderr)

	go writePendingEntry()

	// Larger buffer for systemd's inline coredumps which are typically ~ 14Kb
	r := bufio.NewReaderSize(stdout, 16384)
	cmd.Start()

	for line, _, err := r.ReadLine(); err != io.EOF; line, _, err = r.ReadLine() {
		if err != nil {
			break
		}

		entry := new(SystemdJournalEntry)

		if err = json.Unmarshal(line, &entry); err != nil {
			log.Printf("Could not parse line, skipping: %s\n", line)
			continue
		}

		if pendingEntry == nil {
			pendingEntry = entry
		} else if !pendingEntry.sameSource(entry) {
			pendingEntry.send()
			pendingEntry = entry
		} else {
			if pendingEntry.FullMessage == "" {
				pendingEntry.FullMessage = pendingEntry.Message
			}

			entry.FullMessage = pendingEntry.FullMessage + "\n" + entry.Message
			entry.Message = pendingEntry.Message

			// Replace pending so the higher timestamp keeps writePendingEntry waiting longer for us to append even more
			pendingEntry = entry
		}
	}

	cmd.Wait()
}

func writePendingEntry() {
	for {
		time.Sleep(50 * time.Millisecond)

		if pendingEntry != nil && (time.Now().UnixNano() / 1000 - pendingEntry.Realtime_timestamp) > 100 * 1000 {
			pendingEntry.send()
		}
	}
}