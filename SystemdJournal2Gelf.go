package main

import (
	"encoding/json"
	"fmt"
	"gopkg.in/Graylog2/go-gelf.v2/gelf"
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
	Realtime_timestamp        int64  `json:"__REALTIME_TIMESTAMP,string"`
	Boot_id                   string `json:"_BOOT_ID"`
	Priority                  int32  `json:"PRIORITY,string"`
	Syslog_identifier         string `json:"SYSLOG_IDENTIFIER"`
	Message                   string `json:"MESSAGE"`
	Pid                       string `json:"_PID"`
	Uid                       string `json:"_UID"`
	Systemd_unit              string `json:"_SYSTEMD_UNIT"`
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

	if strings.Contains(this.Message, "\n") {
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
		//	UDP is nonblocking, but the OS stores an error which go will return on the next call.
		//	This means we've already lost a message, but can keep retrying the current one. Sleep to make this less obtrusive
		fmt.Fprintln(os.Stderr, "send - processing paused because of: "+err.Error())
		time.Sleep(SLEEP_AFTER_ERROR)
	}
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

var writer gelf.Writer

const (
	WRITE_INTERVAL             = 50 * time.Millisecond
	SAMESOURCE_TIME_DIFFERENCE = 100 * 1000
	SLEEP_AFTER_ERROR          = 15 * time.Second
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: SystemdJournal2Gelf SERVER:12201 [JOURNALCTL PARAMETERS]")
		os.Exit(1)
	}

	if w, err := gelf.NewUDPWriter(os.Args[1]); err != nil {
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
