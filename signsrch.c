/*
    Copyright 2007 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "show_dump.h"

#ifdef WIN32
    #include <windows.h>
    #include <tlhelp32.h>

    #define LOADDLL         hLib = LoadLibrary(fname);                          \
                            if(!hLib) winerr();
    #define GETFUNC(x,y)    x  = GetProcAddress(hLib, y);                       \
                            if(!x) winerr();
    #define CLOSEDLL        FreeLibrary(hLib);
    HINSTANCE   hLib;

    void winerr(void);
#else
    #include <sys/ptrace.h>

    #define stricmp strcasecmp
    #define stristr strcasestr

    typedef uint32_t    DWORD;

    #define WINAPI
    #define LOADDLL         char    *error;                                     \
                            hLib = dlopen(fname, RTLD_LAZY);                    \
                            if(!hLib) {                                         \
                                fprintf(stderr, "\nError: %s\n\n", dlerror());  \
                                exit(1);                                        \
                            }
    #define GETFUNC(x,y)    x  = dlsym(hLib, y);                                \
                            error = dlerror();                                  \
                            if(error || !x) {                                   \
                            fprintf(stderr, "\nError: %s\n\n", error);          \
                                exit(1);                                        \
                            }
    #define CLOSEDLL        dlclose(hLib);
    void        *hLib;
#endif



#define VER                 "0.1.1"
#define MAX_AND_DISTANCE    3000
#define SIGNFILE            "signsrch.sig"
#define SIGNFILEWEB         "http://aluigi.org/mytoolz/signsrch.sig.zip"



void free_sign(void);
uint8_t *fd_read(uint8_t *name, int *fdlen);
void fd_write(u_char *name, u_char *data, int datasz);
uint32_t search_file(uint8_t *filebuff, int filesize, uint8_t *pattbuff, int pattsize, int and);
uint8_t *process_list(uint8_t *myname, DWORD *mypid, DWORD *size);
uint8_t *process_read(uint8_t *pname, int *fdlen);
void help(uint8_t *arg0);
void std_err(void);



#pragma pack(1)
typedef struct {
    uint8_t     *title;
    uint8_t     *data;
    uint16_t    size;
    uint8_t     and;
} sign_t;
#pragma pack()



int         signs;
sign_t      **sign;
uint32_t    rva,
            sign_alloclen;



#include "signcfg.h"
#include "signcrc.h"



int main(int argc, char *argv[]) {
    uint32_t    i,
                argi,
                found,
                offset,
                filesize,
                listsign   = 0,
                dumpsign   = 0;
    uint8_t     *pid       = NULL,
                *dumpfile  = NULL,
                *filebuff  = NULL,
                *sign_file = SIGNFILE;

    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    fputs("\n"
        "Signsrch "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stderr);

    if(argc < 2) {
        help(argv[0]);
    }

    for(i = 1; i < argc; i++) {
        if(!stricmp(argv[i], "--help")) help(argv[0]);
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) break;
        switch(argv[i][1]) {
            case '-':
            case 'h':
            case '?': {
                help(argv[0]);
                } break;
            case 'l': {
                listsign  = 1;
                } break;
            case 'L': {
                if(!argv[++i]) {
                    printf("\nError: signature number needed\n");
                    exit(1);
                }
                dumpsign  = atoi(argv[i]);
                } break;
            case 's': {
                if(!argv[++i]) {
                    printf("\nError: signature filename needed\n");
                    exit(1);
                }
                sign_file = argv[i];
                } break;
            case 'p': {
                pid = "";
                } break;
            case 'P': {
                if(!argv[++i]) {
                    printf("\nError: process name or pid needed\n");
                    exit(1);
                }
                pid = argv[i];
                } break;
            case 'd': {
                if(!argv[++i]) {
                    printf("\nError: dump file name needed\n");
                    exit(1);
                }
                dumpfile = argv[i];
                } break;
            default: {
                printf("\nError: wrong argument (%s)\n", argv[i]);
                exit(1);
                } break;
        }
    }
    argi = i;

    rva           = 0;
    sign          = NULL;
    signs         = 0;
    sign_alloclen = 0;

    if(pid && !pid[0]) {
        process_list(NULL, NULL, NULL);
        goto quit;
    }

redo:
    if(!listsign && !dumpsign) {
        if(pid) {
            filebuff = process_read(pid, &filesize);
        } else {
            if(i == argc) {
                printf("\nError: you must specify the file to scan\n");
                exit(1);
            }
            filebuff = fd_read(argv[argi], &filesize);
        }
        printf("- %u bytes allocated\n", filesize);
    }

    if(dumpfile) {
        fd_write(dumpfile, filebuff, filesize);
        goto quit;
    }

    if(!sign) {
        printf("- load signatures\n");
        read_cfg(sign_file);
        printf(
            "- %u bytes allocated for the signatures\n"
            "- %u signatures in the database\n",
            sign_alloclen,
            signs);
        if(!dumpsign) signcrc();
    }

    if(dumpsign) {
        dumpsign--;
        if((dumpsign < 0) || (dumpsign >= signs)) {
            printf("\nError: wrong signature number\n");
            exit(1);
        }
        printf("  %s\n", sign[dumpsign]->title);
        show_dump(sign[dumpsign]->data, sign[dumpsign]->size, stdout);
        goto quit;
    }

    if(listsign) {
        printf("\n"
            "  num  description [bits.endian.size]\n"
            "-------------------------------------\n");
        for(i = 0; i < signs; i++) {
            printf("  %-4u %s\n", i + 1, sign[i]->title);
        }
        printf("\n");
        goto quit;
    }

    if(filesize > 10000000) {   // more than 10 megabytes
        printf(
            "- WARNING:\n"
            "  the file loaded in memory is very big so the scanning could take many time\n");
    }

    printf(
        "- start signatures scanning:\n"
        "\n"
        "  offset   num  description [bits.endian.size]\n"
        "  --------------------------------------------\n");

    for(found = i = 0; i < signs; i++) {
        offset = search_file(filebuff, filesize, sign[i]->data, sign[i]->size, sign[i]->and);
        if(offset != -1) {
            printf("  %08x %-4u %s\n", rva + offset, i + 1, sign[i]->title);
            found++;
        }
    }

    printf("\n- %u signatures found in the file\n", found);

    if(filebuff) free(filebuff);
    if(++argi < argc) {
        fputc('\n', stdout);
        goto redo;
    }

quit:
    if(sign) free_sign();
    return(0);
}



void free_sign(void) {
    int     i;

    for(i = 0; i < signs; i++) {
        free(sign[i]->title);
        free(sign[i]->data);
        free(sign[i]);
    }
    free(sign);
}



uint8_t *fd_read(uint8_t *name, int *fdlen) {
    struct  stat    xstat;
    FILE    *fd;
    int     len,
            memsize,
            filesize;
    uint8_t *buff;

    if(!strcmp(name, "-")) {
        printf("- open %s\n", "stdin");
        filesize = 0;
        memsize  = 0;
        buff     = NULL;
        for(;;) {
            if(filesize >= memsize) {
                memsize += 0x7ffff;
                buff = realloc(buff, memsize);
                if(!buff) std_err();
            }
            len = fread(buff + filesize, 1, memsize - filesize, stdin);
            if(!len) break;
            filesize += len;
        }
        buff = realloc(buff, filesize);
        if(!buff) std_err();

    } else {
        printf("- open file \"%s\"\n", name);
        fd = fopen(name, "rb");
        if(!fd) std_err();
        fstat(fileno(fd), &xstat);
        filesize = xstat.st_size;
        buff = malloc(filesize);
        if(!buff) std_err();
        fread(buff, filesize, 1, fd);
        fclose(fd);
    }

    *fdlen = filesize;
    return(buff);
}



void fd_write(u_char *name, u_char *data, int datasz) {
    FILE    *fd;

    printf("- create file %s\n", name);
    fd = fopen(name, "rb");
    if(fd) {
        fclose(fd);
        printf("- file already exists, do you want to overwrite it (y/N)?\n  ");
        fflush(stdin);
        if(tolower(fgetc(stdin)) != 'y') exit(1);
    }
    fd = fopen(name, "wb");
    if(!fd) std_err();
    fwrite(data, datasz, 1, fd);
    fclose(fd);
}



uint32_t search_file(uint8_t *filebuff, int filesize, uint8_t *pattbuff, int pattsize, int and) {
    uint32_t    offset     = 0,
                min_offset = -1;
    uint8_t     *pattlimit,
                *limit,
                *patt,
                *p;

    if(filesize < pattsize) return(-1);

    and >>= 3;
    limit     = filebuff + filesize - pattsize;
    pattlimit = pattbuff + pattsize - and;

    if(and) {
        p = filebuff;
        for(patt = pattbuff; patt <= pattlimit; patt += and) {
            for(p = filebuff; p <= limit; p++) {
                if(!memcmp(p, patt, and)) {
                    offset = p - filebuff;
                    if(offset < min_offset) min_offset = offset;
                    if((offset - min_offset) > MAX_AND_DISTANCE) return(-1);
                    break;
                }
            }
            if(p > limit) return(-1);
        }
        return(min_offset);
    } else {
        for(p = filebuff; p <= limit; p++) {
            if(!memcmp(p, pattbuff, pattsize)) {
                return(p - filebuff);
            }
        }
    }
    return(-1);
}



    // thanx to the extalia.com forum

uint8_t *process_list(uint8_t *myname, DWORD *mypid, DWORD *size) {
#ifdef WIN32
    PROCESSENTRY32  Process;
    MODULEENTRY32   Module;
    HANDLE          snapProcess,
                    snapModule;
    DWORD           retpid = 0;
    int             len;
    BOOL            b;
    uint8_t         tmpbuff[60],
                    *process_name,
                    *module_name,
                    *module_print,
                    *tmp;

    if(mypid) retpid = *mypid;
    if(!myname && !retpid) {
        printf(
            "  pid/addr/size       process/module name\n"
            "  ---------------------------------------\n");
    }

#define START(X,Y) \
            snap##X = CreateToolhelp32Snapshot(Y, Process.th32ProcessID); \
            X.dwSize = sizeof(X); \
            for(b = X##32First(snap##X, &X); b; b = X##32Next(snap##X, &X)) { \
                X.dwSize = sizeof(X);
#define END(X) \
            } \
            CloseHandle(snap##X);

    Process.th32ProcessID = 0;
    START(Process, TH32CS_SNAPPROCESS)
        process_name = Process.szExeFile;

        if(!myname && !retpid) {
            printf("  %-10lu ******** %s\n",
                Process.th32ProcessID,
                process_name);
        }
        if(myname && stristr(process_name, myname)) {
            retpid = Process.th32ProcessID;
        }

        START(Module, TH32CS_SNAPMODULE)
            module_name = Module.szExePath; // szModule?

            len = strlen(module_name);
            if(len >= 60) {
                tmp = strrchr(module_name, '\\');
                if(!tmp) tmp = strrchr(module_name, '/');
                if(!tmp) tmp = module_name;
                len -= (tmp - module_name);
                sprintf(tmpbuff,
                    "%.*s...%s",
                    54 - len,
                    module_name,
                    tmp);
                module_print = tmpbuff;
            } else {
                module_print = module_name;
            }

            if(!myname && !retpid) {
                printf("    %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
            }
            if(!retpid) {
                if(myname && stristr(module_name, myname)) {
                    retpid = Process.th32ProcessID;
                }
            }
            if(retpid && mypid && (Process.th32ProcessID == retpid)) {
                printf("- %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
                *mypid = retpid;
                if(size) *size = Module.modBaseSize;
                return(Module.modBaseAddr);
            }

        END(Module)

    END(Process)

#undef START
#undef END

#else

    system("ps -eo pid,cmd");

#endif

    return(NULL);
}



uint8_t *process_read(uint8_t *pname, int *fdlen) {

#ifdef WIN32

    HANDLE      process;
    DWORD       pid,
                size;
    int         len;
    uint8_t     *baddr,
                *buff;

    if(!pname && !pname[0] && !pid) return(NULL);

    if(pname) {
        len = 0;
        sscanf(pname, "%lu%n", &pid, &len);
        if(len != strlen(pname)) pid = 0;
    }

    baddr = process_list(pid ? NULL : pname, &pid, &size);
    if(!baddr) {
        printf("\nError: process name/PID not found, use -p\n");
        exit(1);
    }
    rva = (uint32_t)baddr;

    printf(
        "- pid %u\n"
        "- base address 0x%08x\n",
        (uint32_t)pid, rva);

    process = OpenProcess(
        PROCESS_VM_READ,
        FALSE,
        pid);
    if(!process) winerr();

    buff = malloc(size);
    if(!buff) std_err();

    if(!ReadProcessMemory(
        process,
        (LPCVOID)baddr,
        buff,
        size,
        &size)
    ) winerr();

    CloseHandle(process);

#else

    pid_t       pid;
    uint32_t    size,
                memsize,
                data;
    uint8_t     *buff;

    pid = atoi(pname);
    rva = 0x8048000;
    printf(
        "- pid %u\n"
        "- try using base address 0x%08x\n",
        pid, rva);

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) std_err();

    size     = 0;
    memsize  = 0;
    buff     = NULL;

    for(errno = 0; ; size += 4) {
        if(!(size & 0xfffff)) fputc('.', stdout);

        data = ptrace(PTRACE_PEEKDATA, pid, (void *)rva + size, NULL);
        if(errno) {
            if(errno != EIO) std_err();
            break;
        }

        if(size >= memsize) {
            memsize += 0x7ffff;
            buff = realloc(buff, memsize);
            if(!buff) std_err();
        }
        memcpy(buff + size, &data, 4);
    }
    fputc('\n', stdout);
    buff = realloc(buff, size);
    if(!buff) std_err();

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) std_err();

#endif

    *fdlen = size;
    return(buff);
}



#ifdef WIN32
void winerr(void) {
    uint8_t     *message = NULL;

    FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      GetLastError(),
      0,
      (char *)&message,
      0,
      NULL);

    if(message) {
        printf("\nError: %s\n", message);
        LocalFree(message);
    } else {
        printf("\nError: unknown Windows error\n");
    }
    exit(1);
}
#endif



void help(uint8_t *arg0) {
    printf("\n"
        "Usage: %s [options] [file1] ... [fileN]\n"
        "\n"
        "-l        list available signatures in the database\n"
        "-L NUM    dumps the data of the signature NUM\n"
        "-s FILE   use the signature file FILE ("SIGNFILE")\n"
        "-p        list the running processes\n"
        "-P PID    use the process/module identified by its pid or part of name/path\n"
        "-d FILE   dump the process memory (like -P) in FILE\n"
        "\n"
        "use - for stdin\n"
        "updated "SIGNFILE": "SIGNFILEWEB"\n"
        "\n", arg0);
    exit(1);
}



void std_err(void) {
    perror("\nError");
    exit(1);
}

