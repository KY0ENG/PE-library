# PE

Portable Executable structure parsing library able to perform analysis upon PE file, memory dump and in running process. Written ages ago, but hopefully someone will find it useful.

## Usage

Depending on target to be analysed, one can use:

* `PE::AnalyseFile` - intended for locally available PE file analysis
* `PE::AnalyseDump` - for raw process memory dump.
* `PE::AnalyseMemory` - able to launch analysis starting from specified address in currently working area.
* `PE::AnalyseProcess` - By specyfing PID one can launch such analysis upon currently running process.

Also, there is couple of potentially interesting functions, such as:
* `PE::InsertShellcode` - for quick and simple PE file infection (new section method)
* `PE::Patch` - for patching PE file
* `PE::ReadBytes` and `PE::WriteBytes` - for read/write in file/process
* `PE::HookIAT` and `PE::HookEAT` - for hooking IAT/EAT entry address (running it on a local file won't do any magic, cause IAT/EAT will be populated by the OS Loader during program's launch anyway, thus clobbering our hook)

File `test.cpp` presents sample usage:

```
	PE pe;

	if( type == process)
	{
		printf( "Analysing process with pid = %d\r\n", (int)dwPID);

		if( strlen( szModule) == 0){
			if( !pe.AnalyseProcess( dwPID) )
				printf( ... );
		}else
			if( !pe.AnalyseProcessModule( dwPID, szModule))
				printf( ... );
	}
	else if( type == dump )
	{
		printf( "Analysing dump file '%s'\r\n", szFile);

		if( !pe.AnalyseDump( szFile) )
			printf( ... );
	}
	else if( type == file )
	{
		printf( "Analysing PE image file '%s'\r\n", szFile);

		if( !pe.AnalyseFile( szFile))
			printf( ... );
	}

	for( unsigned u = 0; u < pe.vImports.size(); u++ )
	{
		printf( "\r\n\tImport: %s", pe.vImports[u].szFunction );
	}
```

Yeah, my PEInfo project should be right away refactored to utilize this library. But nah, I don't have neither time nor willingness to do so.