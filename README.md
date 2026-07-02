![](./media/logo-full-darker-color-smaller.jpg)

# HiveAlert
An [HiveSec](https://github.com/ariannelafraise/hivesec) application that takes YAML rules to react to Auditd events by sending webhook alerts.

## How to use (by an example)
The following Auditd event logs an "accept" syscall from "sshd" executable. It is composed of 3 records
```
type=SYSCALL msg=audit(1782338491.198:398): arch=c000003e syscall=43 success=yes exit=8 a0=3 a1=7ffdf585abf0 a2=7ffdf585ab28 a3=0 items=0 ppid=1 pid=1914 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="sshd" exe="/usr/sbin/sshd" subj=unconfined
type=SOCKADDR msg=audit(1782338491.198:398): saddr=0200E2B4C0A87A540000000000000000
type=PROCTITLE msg=audit(1782338491.198:398): proctitle=737368643A202F7573722F7362696E2F73736864202D44205B6C697374656E65725D2030206F662031302D313030207374617274757073
```

HiveSec will send it to HiveAlert, which will try to match it against its rules. With the following rule, the event will be logged on a Discord webhook, but any other webhooks or custom application endpoints can be used:

> [!NOTE]
> Sometimes, thanks to Auditd, multiple "msg" fields are present in a record. For this reason, you need to append a position number to it. For example, the first msg field will be "msg1" and the second will be "msg2".

```yml
name: ssh-accept
description: Rule that detects "accept" syscall from "sshd" executable
on-fields:
  type: "SYSCALL"
  syscall: "43"
  exe: "/usr/sbin/sshd"
webhook:
  url: "https://discord.com/api/webhooks/xxxx/xxxxxxxxxx"
  payload: |-
    {
      "embeds": [
        {
          "title": "Detected - accept syscall",
          "description": "${0.exe} ${1.saddr} ${2.proctitle}",
          "color": 16554487
        }
      ]
    }
  headers: |-
    {
      "Authorization": "Bearer xxxxxxxxxxx"
    }

```
HiveAlert...
1. Verifies that the fields match
2. Sends the given payload (mandatory) to the given url (mandatory) with the given headers (optional)

The ${variables} are replaced with the values from the Auditd event.

They follow this standard: ${record_index.field.subfield}

For example, ${0.exe} is the exe field of the first record of the event.

## Installation
1. Install [HiveSec](https://github.com/ariannelafraise/hivesec).
2. Clone this repository anywhere you'd like to install it.
3. Register the directory to HiveSec with `sudo hivectl -r /abs/path/to/repo/dir`
4. Add YAML rules in `/etc/hivealert/rules` directory.
5. (Optional) Setup secure permissions on the directories so that rules and application code can't be read without root.
6. Reboot to let HiveSec load the application and rules.
