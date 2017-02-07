SystemdJournal2Gelf
===================

Export entries from systemd's journal and send them to a Graylog server using gelf. This script
is written in Google go to make it easier to compile and distribute to your machines.

Dependencies:
-------------

- this repo includes https://github.com/DECK36/go-gelf
- Google golang


Install / Compile
-----------------

Compile this package by checking out the repo and run:

```
go get github.com/parse-nl/SystemdJournal2Gelf
```

The binary will be compiled in $GOPATH/bin/SystemdJournal2Gelf

Or install the package for:

* [Archlinux](https://aur.archlinux.org/packages/systemdjournal2gelf/)

Running as a service
--------------------

Copy the included `SystemdJournal2Gelf.service` to `/etc/systemd/system`.

Usage:
------

SystemdJournal2Gelf will connect to the server you specify as first argument
and passes all other arguments to journalctl. It prepends these arguments with
--output=json

- Export only the kernel messages
```
SystemdJournal2Gelf localhost:11201 _TRANSPORT=kernel
```

- Perform initial import, reading entire journal
```
SystemdJournal2Gelf localhost:11201 --merge
```

- Monitor the journal
```
SystemdJournal2Gelf localhost:11201 --follow
```

Logging additional properties:
------------------------------

This script supports a special syntax to send additional properties; when you log a JSON encoded
object in the Message field [it Unmarshalls](https://github.com/parse-nl/SystemdJournal2Gelf/blob/master/SystemdJournal2Gelf.go#L87) it for you

License
-------
Copyright (c) 2016-2017, Parse Software Development B.V.

Released under the Simplified BSD license, see LICENSE for details.
