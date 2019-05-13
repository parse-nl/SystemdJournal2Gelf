package main

import (
	"encoding/json"
	"fmt"
	"github.com/DECK36/go-gelf/gelf"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
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
	FullMessage               string `json:"-"`
}

// Strip date from message-content
var startsWithTimestamp = regexp.MustCompile("^20[0-9][0-9][/\\-][01][0-9][/\\-][0123][0-9] [0-2]?[0-9]:[0-5][0-9]:[0-5][0-9][,0-9]{0,3} ")

func (this *SystemdJournalEntry) toGelf() *gelf.Message {
	var extra = map[string]interface{}{
		"Boot_id":      this.Boot_id,
		"Pid":          this.Pid,
		"Uid":          this.Uid,
		"Systemd_unit": this.Systemd_unit,
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
		Facility: this.Syslog_identifier,
		Extra:    extra,
	}
}

// Custom wrapper to support unprintable chars in message
func (this *SystemdJournalEntry) UnmarshalJSON(data []byte) error {
	// use an alias to prevent recursion
	type entryAlias SystemdJournalEntry
	aux := (*entryAlias)(this)

	if err := json.Unmarshal(data, &aux); err == nil {
		this.Message = startsWithTimestamp.ReplaceAllString(this.Message, "")

		return nil
	} else if ute, ok := err.(*json.UnmarshalTypeError); ok && ute.Field == "MESSAGE" && ute.Value == "array" {
		// Include brackets, which is why we subtract and add by one
		len := int64(strings.Index(string(data[ute.Offset:]), `]`)) + 1

		var message []byte
		if err := json.Unmarshal(data[ute.Offset-1:ute.Offset+len], &message); err != nil {
			return err
		}

		// only the failing field is skipped, so we can still use the rest
		this.Message = string(message)

		return nil
	} else {
		return err
	}
}

func (this *SystemdJournalEntry) send() {
	message := this.toGelf()

	for err := writer.WriteMessage(message); err != nil; err = writer.WriteMessage(message) {
		/*
			UDP is nonblocking, but the OS stores an error which GO will return on the next call.
			This means we've already lost a message, but can keep retrying the current one. Sleep to make this less obtrusive
		*/
		fmt.Fprintln(os.Stderr, "send - processing paused because of: "+err.Error())
		time.Sleep(SLEEP_AFTER_ERROR)
	}
}

func (this *SystemdJournalEntry) isJsonMessage() bool {
	return len(this.Message) > 4 && this.Message[0:2] == `{"`
}

type pendingEntry struct {
	sync.RWMutex
	entry *SystemdJournalEntry
}

func (this *pendingEntry) Push(next SystemdJournalEntry) {
	this.Lock()

	if this.entry != nil {
		this.entry.send()
	}

	this.entry = &next
	this.Unlock()
}

func (this *pendingEntry) Clear() {
	if this.entry == nil {
		return
	}

	this.Lock()
	entry := this.entry
	this.entry = nil
	this.Unlock()

	entry.send()
}

func (this *pendingEntry) ClearEvery(interval time.Duration) {
	for {
		time.Sleep(interval)
		this.Clear()
	}
}

var writer *gelf.Writer

const (
	WRITE_INTERVAL             = 50 * time.Millisecond
	SAMESOURCE_TIME_DIFFERENCE = 100 * 1000
	SLEEP_AFTER_ERROR          = 15 * time.Second
)

func main() {
	if len(os.Args) < 3 {
		panic("usage: SystemdJournal2Gelf SERVER:12201 [JOURNALCTL PARAMETERS]")
	}

	if w, err := gelf.NewWriter(os.Args[1]); err != nil {
		panic("while connecting to Graylog server: " + err.Error())
	} else {
		writer = w
	}

	journalArgs := []string{"--all", "--output=json"}
	journalArgs = append(journalArgs, os.Args[2:]...)
	cmd := exec.Command("journalctl", journalArgs...)

	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	go io.Copy(os.Stderr, stderr)
	d := json.NewDecoder(stdout)

	var pending pendingEntry
	go pending.ClearEvery(WRITE_INTERVAL)
	cmd.Start()

	for {
		var entry SystemdJournalEntry
		if err := d.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}

			cmd.Process.Kill()
			panic("could not parse journal output: " + err.Error())
		}

		pending.Push(entry)

		// Prevent saturation and throttling
		time.Sleep(1 * time.Millisecond)
	}

	cmd.Wait()

	pending.Clear()
}
