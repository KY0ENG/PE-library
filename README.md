# PE

Lightweight Portable Executable format parsing library for Windows programs. Handy for malware analysis and development purposes.
Probably _really_ buggy, potentially vulnerable to all sorts of memory corruptions :-) 
Written agos ago, refactored, fixed, improved, enhanced ad-hoc without a will to rewrite it properly or attempt to find & fix any outstanding memory handling issues.


## Usage

Following analysis endpoints are exposed:

* `PE::AnalyseFile` - locally available files analysis
* `PE::AnalyseDump` - raw process memory dump analysis
* `PE::AnalyseMemory` - analyses memory region mapped at specified process
* `PE::AnalyseProcess` - analyses remote process main module.
* `PE::AnalyseProcessModule` - analyses specifed module mapped in the remote process virtual memory.

Other exposed functionality worth taking a shot:

* `PE::InsertShellcode` - inserts input shellcode into a newly injected PE section
* `PE::ReadBytes` and `PE::WriteBytes` - file/process I/O
* `PE::HookIAT` and `PE::HookEAT` - for hooking IAT/EAT thunks (running it on a local file won't do any magic, cause IAT/EAT will be populated by the OS Loader during program's launch anyway, thus clobbering our hook)
* `PE::CreateSection` and `PE::RemoveSection` - adds/remove PE section
* `PE::HasOverlay` and `PE::ReadOverlay` - for working with file's overlay
* `PE::UpdateHeaders` - adjusts OptionalHeader after any PE structures field was altered.
* `PE::ReadSection` - reads specified section bytes.


## Demo

For demo purposes of how to use the library, the small utility `peParser` is included.
Its use is straightforward:

```
cmd> peParser86.exe

Usage:

    1) Analyse file:
    cmd> peParser file <filepath>

    2) Analyse process:
    cmd> peParser process <PID>

    3) Analyse process' module:
    cmd> peParser module <PID> <moduleName|0xModuleAddress>

    4) Analyse dump file:
    cmd> peParser dump <filepath>

    5) Analyse injected, not-mapped (MEM_PRIVATE) shellcode:
    cmd> peParser memory <PID> <address>
```

## Known Issues

Billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions and billions [...] and billions of programming errors were probably made in its implementation. As said, I've got no will to find & fix them. 

My typical use of this library is for the Malware Development for Red Team purposes. Such use case requires merely a lightweight codebase capable of analysing mostly well-structured system binaries and for these needs a current implementation excels pretty well.

You are free to go ahead and train your vulnerability analysis & exploitation skills by crafting dodgy PE structures attempting to exploit my tasty bugs. :-) Ohhh, and if you do - please do mind opening an issue as I would be keen on fixing them eventually!



---

### ☕ Show Support ☕

This and other projects are outcome of sleepless nights and **plenty of hard work**. If you like what I do and appreciate that I always give back to the community,
[Consider buying me a coffee](https://github.com/sponsors/mgeeky) _(or better a beer)_ just to say thank you! 💪 

---

## Author

```   
   Mariusz Banach / mgeeky, 21
   <mb [at] binary-offensive.com>
   (https://github.com/mgeeky)
```
