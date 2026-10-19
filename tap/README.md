# plasma-tap (krabsetw ETW tap)

C++ sidecar for Plasma that streams the "gap providers" Sysmon/WHIDS do not
own — PowerShell (full ETW fidelity), WMI-Activity, DNS-Client, .NET Runtime
(narrow keywords), Schannel — scores every event **in memory** against a
fixed rules file, and writes **matches only** as JSONL.

Lake-less by construction: raw streams live in the ETW transport and die
with the process; nothing but capped match records ever touches disk. No
service, no persistence — the tap runs on demand for `--for` seconds.

## Build (Windows, MSVC x64)

```bat
git clone --depth 1 https://github.com/microsoft/krabsetw
cl /nologo /std:c++17 /EHsc /O2 /W3 /I krabsetw\krabs plasma-tap.cpp ^
   /Fe:plasma-tap.exe tdh.lib advapi32.lib
```

CI does exactly this (see .github/workflows). krabsetw is MIT; this file is
part of Plasma's own code.

## Run

```bat
plasma-tap.exe --rules plasma-tap-rules.txt --out matches.jsonl ^
               --providers powershell,wmi,dns --for 300 --max-matches 500
plasma-tap.exe --rules plasma-tap-rules.txt --selftest
```

Requires an elevated prompt (StartTrace needs admin). Failures are printed
as JSON on stdout with exit 3 — never silent, never pretended.

## Rules

One rule per line, 7 pipe-separated fields (generated from
`sensors/plasma-tap-rules.json` by `plasma tap` / `plasma.tap.build_rules_txt`):

```
name|provider|event_id|field|substr|severity|technique
```

`event_id` 0 = any; `field` empty = event name, `*` = all parsed fields;
empty `substr` = match-all for that provider+id. Matching is
case-insensitive substring — deliberately dumb, deterministic and auditable.
