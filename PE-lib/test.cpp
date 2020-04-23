
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
    DWORD dwPID = 0;
    char szFile[MAX_PATH] = "";
    char szModule[MAX_PATH]="";

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
            if (!pe.AnalyseProcess(dwPID, true))
            {
                printf("[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError());
            }
        }
        else
        {
            if (!pe.AnalyseProcessModule(dwPID, szModule, false))
            {
                printf("[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError());
            }
        }

    }
    else if( type == dump )
    {
        printf( "Analysing dump file '%s'\r\n", szFile);

        if (!pe.AnalyseDump(szFile, true))
        {
            printf("[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError());
        }

    }
    else if( type == file )
    {
        printf( "Analysing PE image file '%s'\r\n", szFile);

        if (!pe.AnalyseFile(szFile, true))
        {
            printf("[!] Error during analysis: %d (0x%X)\r\n", (int)pe.GetError(), (int)pe.GetError());
        }
    }

    if (pe.vImports.size())
    {
        for (size_t u = 0; u < pe.vImports.size() - 1; u++)
        {
            printf("\r\nImport (%d):\n\t- Name: %s!%s\n\t- Hint: %x\n\t- ThunkRVA: 0x%08x\n\t- wOrdinal: %d\n", 
                u,
                pe.vImportDescriptors[pe.vImports[u].uImpDescriptorIndex].szName, 
                pe.vImports[u].szFunction,
                pe.vImports[u].dwHint,
                static_cast<DWORD>(pe.vImports[u].dwThunkRVA),
                pe.vImports[u].wOrdinal
            );
        }
    }

    printf("\r\n\r\n");

    if (pe.vExports.size())
    {
        for (size_t u = 0; u < pe.vExports.size() - 1; u++)
        {
            printf("\r\nExport (%d):\n\t- Name: %s\n\t- Pointer: 0x%p\n\t- Forwarder: %s\n\t- ThunkRVA: 0x%08x\n\t- wOrdinal: %x\n", 
                u,
                pe.vExports[u].szFunction,
                pe.vExports[u].dwPtrValue,
                pe.vExports[u].szForwarder,
                static_cast<DWORD>(pe.vExports[u].dwThunkRVA),
                pe.vExports[u].wOrdinal
            );
        }
    }
    
    //pe.HookIAT("RtlUnwind", 0x1122334455667788);

    return 0;
}
