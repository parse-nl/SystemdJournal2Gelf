SystemdJournal2Gelf
===================

Export entries from systemds' journal and send them to a graylog server using gelf. This script
is written in go to make it easier to compile and distribute to your machines.

Tested on go1.1 on Archlinux using systemd-204. Inspired by https://github.com/systemd/journal2gelf


Dependencies:
-------------

- https://github.com/SocialCodeInc/go-gelf
- Google go


Compile
-------

```
go get github.com/SocialCodeInc/go-gelf/gelf
go build SystemdJournal2Gelf.go
```


Running as a service
--------------------

Copy the included `SystemdJournal2Gelf.service` to `/etc/systemd/system`.

Usage:
------

SystemdJournal2Gelf will connect to the server you specify as first argument
and passes all other arguments to journalctl. It prepends these arguments with
--mode=json

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


License
-------
Copyright (c) 2013, React B.V.

Released under the Simplified BSD license, see LICENSE for details.
