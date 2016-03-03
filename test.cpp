
#include <cstdio>
#include <cstdlib>
#include <ctype.h>
#include "getopt.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "PE.h"

int main( int argc, char **argv)
{
	enum analyse
	{
		process = 0,
		file,
		dump
	};

	analyse type;
	DWORD dwPID;
	char szFile[MAX_PATH] = "";
	char szModule[MAX_PATH]="";

#ifdef _DEBUG
	char *szArgv1 = "-f";
	char *szArgv2 = "C:\\WINDOWS\\System32\\calc.exe";
	argv[1] = szArgv1;
	argv[2] = szArgv2;
	argc = 3;
#endif

	if( argc == 1)
	{
		printf( "Usage: %s [options]\r\n\r\n\t-p PID\t\tSpecifies process to analyse\r\n\t-f FILE"\
				"\t\tSpecifies file to analyse\r\n\t-d DUMP\t\tSpecifies dump file to analyse\r\n"\
				"-m MODULENAME\tPerforms process's module analysis. NEED to specify -p PID !\r\n", argv[0] );
		exit(1);
	}

	opterr = 0;
	char c;

	// Parse options
	while( (c = getopt(argc, (TCHAR* const*)argv, (TCHAR*)"p:f:d:m:" )) != -1)
	{
		switch( c)
		{
			case 'p':
				// Process
				type = process;
				dwPID = atoi((const char*)optarg);
				break;

			case 'f':
			case 'd':
				if( c == 'f') 	type = file;
				else			type = dump;

				strcpy( szFile, (const char*)optarg);
				break;

			case 'm':
				strcpy( szModule, (const char*)optarg);
				break;

			case '?':
				printf( "[!] Option '%c' requires an argument !", optopt);
				exit(1);

			default:
				printf( "[!] Unknown option: '%c'. Correct it.\r\n", c);
				exit(1);
		}
	}

	if( dwPID == 0 && strlen( szModule) > 0)
	{
		puts("[!] You need to specify PID of process of which module you want to analyse!\r\n");
		exit(1);
	}


	PE pe;

	if( type == process)
	{
		printf( "Analysing process with pid = %d\r\n", (int)dwPID);

		if( strlen( szModule) == 0){
			if( !pe.AnalyseProcess( dwPID) )
				printf( "[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError() );
		}else
			if( !pe.AnalyseProcessModule( dwPID, szModule))
				printf( "[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError() );

	}
	else if( type == dump )
	{
		printf( "Analysing dump file '%s'\r\n", szFile);

		if( !pe.AnalyseDump( szFile) )
			printf( "[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError() );

	}
	else if( type == file )
	{
		printf( "Analysing PE image file '%s'\r\n", szFile);

		if( !pe.AnalyseFile( szFile))
			printf( "[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError() );

	}

	for( unsigned u = 0; u < pe.vImports.size(); u++ )
	{
		printf( "\r\n\tImport: %s", pe.vImports[u].szFunction );
	}

	return 0;
}
