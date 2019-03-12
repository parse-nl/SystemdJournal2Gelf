package main

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalEntry(t *testing.T) {
	entry := SystemdJournalEntry{}

	err := json.Unmarshal([]byte(`{
        "MESSAGE" : "Linux version 4.20.6-arch1-1-ARCH (builduser@heftig-32156) (gcc version 8.2.1 20181127 (GCC)) #1 SMP PREEMPT Thu Jan 31 08:22:01 UTC 2019",
        "PRIORITY" : "5",
        "__REALTIME_TIMESTAMP" : "1549067421724300",
        "_TRANSPORT" : "kernel",
        "SYSLOG_FACILITY" : "0",
        "SYSLOG_IDENTIFIER" : "kernel",
        "_HOSTNAME" : "machine.nl",
        "_BOOT_ID" : "61c0e40c739f4f009c785cef13b46e17",
		"_UID" : "99",
		"_PID" : "1234"
	}`), &entry)

	AssertNotError(t, err)

	gelf := entry.toGelf()
	AssertEquals(t, "machine.nl", gelf.Host)
	AssertEquals(t, "Linux version 4.20.6-arch1-1-ARCH (builduser@heftig-32156) (gcc version 8.2.1 20181127 (GCC)) #1 SMP PREEMPT Thu Jan 31 08:22:01 UTC 2019", gelf.Short)
	AssertEquals(t, "", gelf.Full)
	AssertEquals(t, float64(1549067421.7243001), gelf.TimeUnix)
	AssertEquals(t, int32(5), gelf.Level)
	AssertEquals(t, "kernel", gelf.Facility)

	AssertEquals(t, 3, len(gelf.Extra))
	AssertEquals(t, "61c0e40c739f4f009c785cef13b46e17", gelf.Extra["Boot_id"])
	AssertEquals(t, "99", gelf.Extra["Uid"])
	AssertEquals(t, "1234", gelf.Extra["Pid"])

}

func TestJsonMessageOverridesNormalProperties(t *testing.T) {
	entry := SystemdJournalEntry{}

	err := json.Unmarshal([]byte(`{
        "_HOSTNAME" : "machine.nl",
        "MESSAGE" : "{\"Message\":\"actually something else\",\"FullMessage\":\"additional data\"}",
        "SYSLOG_IDENTIFIER" : "kernel"
	}`), &entry)

	AssertNotError(t, err)

	gelf := entry.toGelf()

	AssertEquals(t, "machine.nl", gelf.Host)
	AssertEquals(t, "actually something else", gelf.Short)
	AssertEquals(t, "additional data", gelf.Full)
	AssertEquals(t, "kernel", gelf.Facility)
	AssertEquals(t, 3, len(gelf.Extra))
}

func TestJsonMessageIncludeDataInExtra(t *testing.T) {
	entry := SystemdJournalEntry{}

	err := json.Unmarshal([]byte(`{
        "_HOSTNAME" : "machine.nl",
		"MESSAGE" : "{\"Message\":\"actually something else\",\"stuff\":\"things and stuff and more like that\"}",
        "SYSLOG_IDENTIFIER" : "kernel"
	}`), &entry)

	AssertNotError(t, err)

	gelf := entry.toGelf()

	AssertEquals(t, "machine.nl", gelf.Host)
	AssertEquals(t, "actually something else", gelf.Short)
	AssertEquals(t, "kernel", gelf.Facility)
	AssertEquals(t, 4, len(gelf.Extra))
	AssertEquals(t, "things and stuff and more like that", gelf.Extra["stuff"])
}

func TestUnmarshalUnprintableEntry(t *testing.T) {
	entry := SystemdJournalEntry{}

	err := json.Unmarshal([]byte(`{
        "_HOSTNAME" : "machine.nl",
        "MESSAGE" : [ 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 98, 105, 110, 97, 114, 121, 32, 118, 97, 108, 117, 101, 32, 7 ],
        "SYSLOG_IDENTIFIER" : "kernel"
	}`), &entry)

	AssertNotError(t, err)

	gelf := entry.toGelf()
	AssertEquals(t, "this is a binary value \a", gelf.Short)

	AssertEquals(t, "kernel", gelf.Facility)
	AssertEquals(t, "machine.nl", gelf.Host)

}

func AssertEquals(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		t.Errorf("AssertEquals: %[1]T(%#[1]v) does not match %[2]T(%#[2]v))", actual, expected)
	}
}

func AssertNotEquals(t *testing.T, expected, actual interface{}) {
	if expected == actual {
		t.Errorf("AssertNotEquals: %[1]T(%#[1]v) unexpectedly matches %[2]T(%#[2]v)", actual, expected)
	}
}

func AssertError(t *testing.T, err interface{}) {
	_, ok := err.(error)

	if !ok {
		t.Errorf("AssertError: %[1]T(%#[1]v) is not an error", err)
	}
}

func AssertSpecificError(t *testing.T, err interface{}, specific error) {
	_, ok := err.(error)

	if !ok {
		t.Errorf("AssertError: %[1]T(%#[1]v) is not an error", err)
	} else if specific != nil && err != specific {
		t.Errorf("AssertError: %[1]T(%#[1]v) is not an %[1]T(%#[1]v)", err, specific)
	}
}

func AssertNotError(t *testing.T, err interface{}) {
	_, ok := err.(error)

	if ok {
		t.Errorf("AssertNotError: %#[1]v is unexpectedly an error", err)
	}
}
