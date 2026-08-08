# After Hours — Hunting a Fileless WMI Backdoor | TryHackMe Hacker Holidays 2026

> **TryHackMe Hacker Holidays 2026 — Room 12: After Hours**

> *Reverse-engineering a Windows WMI repository, decoding PowerShell, extracting an in-memory .NET payload, and analyzing the persistence chain — from a MacBook Air M1 and Kali Linux.*

*Disclaimer: This write-up documents an authorized TryHackMe CTF challenge performed in a controlled training environment. All commands shown are used for forensic analysis of challenge-provided artifacts. No real-world systems were targeted, and the recovered executable was analyzed statically rather than executed.*


![TryHackMe Hacker Holidays 2026](<img width="1400" height="633" alt="image" src="https://github.com/user-attachments/assets/5628ec21-63ea-4ebf-a8f1-f19a3bbca059" />)

## Introduction

This is my first write-up from **TryHackMe’s Hacker Holidays 2026**, and I’m jumping straight into **Room 12 — After Hours**.

I haven’t written about the previous rooms in the event, but this one stood out enough that I wanted to document the full investigation. Instead of the usual web application, exposed service, or straightforward executable analysis, *After Hours* drops us into **Windows forensics** and gives us a small collection of WMI repository files to investigate.

The files provided were:

```
INDEX.BTR
MAPPING1.MAP
MAPPING2.MAP
MAPPING3.MAP
OBJECTS.DATA
```

That’s all we start with.

There is no obvious malware sample sitting in front of us, no source code, and definitely no flag waiting to be found with a simple `strings | grep THM`.

The real question is:

> ***What happened on this Windows system, and what is hiding inside its WMI repository?***

As I worked through the artifacts, what initially looked like a handful of obscure Windows database files turned into a much more interesting chain involving **WMI persistence, encoded PowerShell, a custom WMI class being used as covert storage, compressed payload data, and a .NET executable designed to be loaded directly into memory.**

The investigation eventually looked like this:

```
  WMI Repository
        ↓
Permanent WMI Event Consumer
        ↓
Encoded PowerShell
        ↓
  Custom WMI Class
        ↓
Base64-Encoded ConfigData
        ↓
Raw DEFLATE Compression
        ↓
   .NET Payload
        ↓
Embedded Windows Command
        ↓
Another Base64 Layer
        ↓
       Flag
```

There was one additional challenge on my side:

**I was solving everything from a MacBook Air M1.**

The artifacts came from Windows, the payload was a Windows executable, and the persistence mechanism was entirely Windows-specific. But because this was a forensic investigation, I didn’t actually need a Windows machine to understand what happened.

Using mostly:

```
strings
grep
file
base64
Python
```

I was able to reconstruct the complete execution chain without running the recovered payload at all.

And that ended up being one of my favorite parts of this room.

So in this write-up, rather than simply listing the answers, I’m going to walk through **how I approached the files, why each artifact mattered, what each command actually tells us, and how one clue naturally led to the next.**

Let’s get into **After Hours**.

## Step 1 — Start With the Obvious: Search the Repository

I started with `OBJECTS.DATA` and looked for anything related to WMI persistence, PowerShell, or suspicious custom classes.

### macOS

```
strings OBJECTS.DATA | grep -Ei \
'CommandLineEventConsumer|EventFilter|powershell|HardwareTelemetry|ConfigData'
```

### Kali Linux

```
strings OBJECTS.DATA | grep -Ei \
'CommandLineEventConsumer|EventFilter|powershell|HardwareTelemetry|ConfigData'
```

Same command on both platforms.


The interesting hits included:

```
CommandLineEventConsumer
Win32_HardwareTelemetry
ConfigData
powershell
```

The presence of `CommandLineEventConsumer` was the first real clue. WMI event consumers can execute commands when an associated event is triggered, which makes them useful for persistence.

## Step 2 — Check the WMI Index

Next I searched `INDEX.BTR`:

```
strings INDEX.BTR | grep -Ei \
'CommandLineEventConsumer|powershell|EngineTelemetry|HardwareTelemetry'
```

This works the same way on macOS and Kali.


One of the names that appeared was:

```
EngineTelemetryConsumer
```

Alongside it was a PowerShell command using:

```
-enc
```

which is short for:

```
-EncodedCommand
```

That told me the next layer was Base64-encoded PowerShell.

## Step 3 — Decode the PowerShell

PowerShell `-EncodedCommand` normally uses **UTF-16LE**, so simply Base64-decoding it as ASCII is not enough.

I used Python:

```
python3 - <<'PY'
import re
import base64
data = open("INDEX.BTR", "rb").read()
m = re.search(
    rb'-enc\s+([A-Za-z0-9+/=]{200,})',
    data,
    re.I
)
if not m:
    raise SystemExit("Encoded PowerShell not found")
decoded = base64.b64decode(m.group(1))
print(decoded.decode("utf-16le"))
PY
```

This works unchanged on both macOS and Kali Linux.


The important part of the decoded script was:

```
$file = ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').Properties['ConfigData'].Value;
```

followed by Base64 decoding, DEFLATE decompression, and finally:

```
[Reflection.Assembly]::Load(...)
```

So the PowerShell itself gave us the next stage:

```
Win32_HardwareTelemetry.ConfigData
        ↓
     Base64
        ↓
     DEFLATE
        ↓
.NET assembly
```

## Step 4 — Find the Hidden ConfigData

Back in `OBJECTS.DATA`, I searched around the suspicious WMI class:

```
strings OBJECTS.DATA | grep -A3 -B3 "Win32_HardwareTelemetry"
```

Same command on macOS and Kali.


Near that class was a large Base64-looking blob.

Rather than copy it manually, I extracted it with Python.

## Step 5 — Extract and Decompress the Payload

```
python3 - <<'PY'
import re
import base64
import zlib
data = open("OBJECTS.DATA", "rb").read()
start = data.find(b"Win32_HardwareTelemetry")
if start == -1:
    raise SystemExit("Win32_HardwareTelemetry not found")
chunk = data[start:start + 10000]
matches = re.findall(
    rb'[A-Za-z0-9+/]{500,}={0,2}',
    chunk
)
for encoded in matches:
    try:
        compressed = base64.b64decode(encoded)
        payload = zlib.decompress(
            compressed,
            -15
        )
        if payload.startswith(b"MZ"):
            open("payload.exe", "wb").write(payload)
            print("[+] Extracted payload.exe")
            print("[+] Size:", len(payload), "bytes")
            break
    except Exception:
        pass
PY
```

Again, this runs the same way on both systems.


The `-15` tells Python to treat the data as **raw DEFLATE**, which matches what the PowerShell loader was doing.

The `MZ` check is also important because Windows PE executables normally begin with the `MZ` signature.

## Step 6 — Identify the Payload

### macOS

```
file payload.exe
```

### Kali Linux

```
file payload.exe
```

Same result conceptually: it should identify the file as a Windows PE executable and .NET assembly.


At this point I still did not execute the file.

There was no need.

Static analysis was enough.

## Step 7 — Look for Strings in the .NET Binary

Start with:

```
strings payload.exe
```

On Kali, GNU `strings` also makes UTF-16LE extraction easier:

```
strings -el payload.exe
```

That `-el` option means:

```
16-bit little-endian strings
```

which is useful for Windows and .NET binaries.

On macOS, I used Python instead:

```
python3 - <<'PY'
import re
data = open("payload.exe", "rb").read()
text = data.decode(
    "utf-16le",
    errors="ignore"
)
for word in re.findall(
    r'[\x20-\x7e]{4,}',
    text
):
    print(word)
PY
```


Among the extracted strings, one stood out:

```
/c net user patch VEhNe1A0dG.....2QwMHJ9 /add
```


That command was the final major clue.

## Step 8 — Decode the Last Base64 String

The value being used as the password looked exactly like Base64:

```
VEhNe1A0dG.....2QwMHJ9
```

### macOS

```
echo 'VEhNe1A0dG.....2QwMHJ9' | base64 -D
```

### Kali Linux

```
echo 'VEhNe1A0dG.....2QwMHJ9' | base64 -d
```

That is one of the few places where the command differs slightly.


And that gives the flag:

```
THM{********}
```

## Challenge Completion

> *I’ve intentionally redacted the flag so anyone following this write-up still has to perform the final decoding step themselves.*

```
THM{********}
```

**What the Full Chain Looked Like**

Once everything was pieced together, the attack chain made a lot more sense:

```
WMI Repository
      ↓
CommandLineEventConsumer
      ↓
Encoded PowerShell
      ↓
Win32_HardwareTelemetry.ConfigData
      ↓
Base64 Decode
      ↓
Raw DEFLATE
      ↓
.NET Executable
      ↓
Embedded net user Command
      ↓
Final Base64 Decode
      ↓
Flag
```

What I liked about this room was that every stage pointed naturally toward the next one.

The PowerShell told us which WMI property to inspect.

The code told us which encoding and compression formats were being used.

The recovered .NET payload then revealed the final command.

No guessing was really necessary.

## macOS vs Kali Linux

Most of the workflow is identical on both systems.

The main differences are small:

| Task | macOS | Kali Linux |
|---|---|---|
| Base64 decode | `base64 -D` | `base64 -d` |
| ASCII strings | `strings file` | `strings file` |
| UTF-16LE strings | Python works best | `strings -el file` |
| File identification | `file` | `file` |
| Python scripts | `python3` | `python3` |

So even though the artifacts and payload are Windows-specific, the investigation itself is very portable.

I solved it on a **MacBook Air M1**, but the same approach works perfectly well from Kali.

## Closing Thoughts

*After Hours* was a good reminder that persistence does not always live in obvious places like registry Run keys, scheduled tasks, or startup folders.

Here, WMI acted as both a persistence mechanism and a storage location for the next-stage payload.

What looked like a few boring repository files eventually exposed:

```
WMI persistence
PowerShell
Base64
DEFLATE
.NET
in-memory loading
local account creation
```

And the best part was that I never had to execute the recovered Windows payload.

Everything could be understood through static analysis.

For me, that made this room much more interesting than simply finding the flag.

It became a small forensic investigation where every artifact had something to say — as long as I kept following the evidence.
