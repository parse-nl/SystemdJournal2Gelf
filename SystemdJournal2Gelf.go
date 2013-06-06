package main

import (
	"encoding/json"
	"github.com/SocialCodeInc/go-gelf/gelf"
	"io"
	"bufio"
	"strconv"
	"log"
	"os/exec"
	"time"
	"os"
	"errors"
)

/*
	http://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
	https://github.com/Graylog2/graylog2-docs/wiki/GELF
*/
type SystemdJournalEntry struct {
	Cursor string			`json:"__CURSOR"`
	Realtime_timestamp string	`json:"__REALTIME_TIMESTAMP"`
	Monotonic_timestamp string	`json:"__MONOTONIC_TIMESTAMP"`
	Boot_id string			`json:"_BOOT_ID"`
	Transport string		`json:"_TRANSPORT"`
	Priority string			`json:"PRIORITY"`
	Syslog_facility string		`json:"SYSLOG_FACILITY"`
	Syslog_identifier string	`json:"SYSLOG_IDENTIFIER"`
	Message string			`json:"MESSAGE"`
	Pid string			`json:"_PID"`
	Uid string			`json:"_UID"`
	Gid string			`json:"_GID"`
	Comm string			`json:"_COMM"`
	Exe string			`json:"_EXE"`
	Cmdline string			`json:"_CMDLINE"`
	Systemd_cgroup string		`json:"_SYSTEMD_CGROUP"`
	Systemd_session string		`json:"_SYSTEMD_SESSION"`
	Systemd_owner_uid string	`json:"_SYSTEMD_OWNER_UID"`
	Source_realtime_timestamp string`json:"_SOURCE_REALTIME_TIMESTAMP"`
	Machine_id string		`json:"_MACHINE_ID"`
	Hostname string			`json:"_HOSTNAME"`
}

func (this *SystemdJournalEntry) toGelf() (*gelf.Message, error) {
	timestamp, err := strconv.ParseInt(this.Realtime_timestamp, 10, 64)
	if err != nil {
		return nil, errors.New(this.Cursor+" - error in timestamp: "+ err.Error())
	}

	level, err := strconv.ParseInt(this.Priority, 10, 32)
	if err != nil {
		return nil, errors.New(this.Cursor+" - error in priority: "+ err.Error())
	}

	return &gelf.Message{
		Version:	"1.0",
		Host:		this.Hostname,
		Short:		this.Message,
		TimeUnix:	timestamp / 1000 / 1000,
		Level:		int32(level),
		Facility:	this.Transport,
		Extra:		map[string] interface {}{
			"Boot_id":	this.Boot_id,
			"Pid":		this.Pid,
			"Uid":		this.Uid,
		},
	}, nil
}

func main() {
	if len(os.Args) < 3 {
		log.Fatal("Pass server:12201 as first argument and append journalctl parameters to use")
	}

	serverAddr := os.Args[1]
	journalArgs := os.Args[1:]
	journalArgs[0] = "--output=json"

	cmd := exec.Command("journalctl", journalArgs...)

	gelfWriter, err := gelf.NewWriter(serverAddr)
	if err != nil {
		log.Fatalf("While connecting to Graylog server: %s", err)
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go io.Copy(os.Stderr, stderr)

	// Larger buffer for systemd's inline coredumps which are typically ~ 14Kb
	r := bufio.NewReaderSize(stdout, 16484)
	cmd.Start()

	for line, _, err := r.ReadLine(); err != io.EOF; line, _, err = r.ReadLine() {
		if err != nil {
			break
		}

		entry := new(SystemdJournalEntry);
		err = json.Unmarshal(line, &entry)

		if err != nil {
			log.Printf("Could not parse line, skipping: %s", line)
			continue
		}

		message, err := entry.toGelf();

		if err != nil {
			log.Print(err)
			continue
		} else {
			go gelfWriter.WriteMessage(message)

			// Prevent saturation and throttling
			time.Sleep(2 * time.Millisecond)
		}
	}

	cmd.Wait()
}
