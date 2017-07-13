#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma pack(push)
#pragma pack(1)
typedef struct  
{
	//60               pushad    
	BYTE pushad;				//	60
	//B9 05 00 00 00   mov         ecx,5			//	拷贝个数
	BYTE move_eax_5;			//	B9
	DWORD move_eax_5_NUMBER;	//	5
	//BE 11 11 11 11   mov         esi,11111111h	//	源地址（后面存放的5字节）
	BYTE move_esi;				//	BE
	DWORD move_esi_NUMBER;		//	0xXXXXXXXX
	//BF 11 11 11 11   mov         edi,11111111h	//	目的地址（EP）
	BYTE move_edi;				//	BF
	DWORD move_edi_NUMBER;		//	0xXXXXXXXX
	//F3 A4            rep movsb					//	拷贝5个字节
	BYTE rep_movsb[2];			//	F3 A4
	//68 11 11 11 11   push        11111111h		//	DLL_PATH
	BYTE push_string;			//	68
	DWORD push_string_point;	//	0xXXXXXXXX
	//B8 11 11 11 11   mov         eax,11111111h	//	LoadLibraryA
	BYTE move_eax;				//	B8
	DWORD move_eax_NUMBER;		//	0xXXXXXXXX
	//FF D0            call        eax  
	BYTE call_eax[2];			//	FF D0
	//61               popad
	BYTE popad;					//	61
	//				   jmp 0x11111111
	BYTE jmp;					//	E9
	DWORD jmp_NUMBER;			//	0xXXXXXXXX

	BYTE bufEPCode[8];
	BYTE dll_path[260];
}ShellCode;
#pragma pack(pop)

void InitShellCode(ShellCode *sc)
{
	BYTE buf[] = {0x60, 0xB9, 0x05, 0x00, 0x00, 0x00, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0x00, 0x00,
	0xF3, 0xA4, 0x68, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x61, 0xE9, 0x00, 0x00, 0x00, 0x00};
	memcpy(sc , buf , sizeof(buf));
}

typedef struct 
{
	DWORD dwImageBase;
	DWORD dwEntryPointAddressInProcess;
	BYTE byteEntryPointCode[0x1000];
	DWORD dwEntryPointCodeLen;
}EntryPointStruct;

int GetDestProcessEPInfor(PROCESS_INFORMATION *pi, EntryPointStruct *eps)
{
	CONTEXT ctx = {0,};
	PIMAGE_DOS_HEADER       pIDH = NULL;
	PIMAGE_OPTIONAL_HEADER  pIOH = NULL;
	ctx.ContextFlags = CONTEXT_FULL;
	if( !GetThreadContext(pi->hThread, &ctx) )
	{
		return FALSE;
	}

	if( !ReadProcessMemory(
		pi->hProcess, 
		(LPCVOID)(ctx.Ebx + 8),     // ctx.Ebx = PEB, ctx.Ebx + 8 = PEB.ImageBase
		&eps->dwImageBase, 
		sizeof(DWORD), 
		NULL) )
	{
		return FALSE;
	}

	if (!ReadProcessMemory(pi->hProcess, (LPVOID)eps->dwImageBase, eps->byteEntryPointCode, 0x1000, NULL))
	{
		return FALSE;
	}
	eps->dwEntryPointCodeLen = 0x1000;

	pIDH = (PIMAGE_DOS_HEADER)(eps->byteEntryPointCode);
	pIOH = (PIMAGE_OPTIONAL_HEADER)((eps->byteEntryPointCode) + pIDH->e_lfanew + 0x18);
	eps->dwEntryPointAddressInProcess = eps->dwImageBase + pIOH->AddressOfEntryPoint;	//	目标进程中的OEP偏移

	if (!ReadProcessMemory(pi->hProcess, (LPVOID)eps->dwEntryPointAddressInProcess, eps->byteEntryPointCode, 0x1000, NULL))
	{
		return FALSE;
	}
	eps->dwEntryPointCodeLen = 0x1000;

	return 1;
}

int InjectDllToProcess(char *dll_path, PROCESS_INFORMATION *pi)
{
	char strFile[260] = "";
	BYTE byteBuffer[0x1000] = "";
	BOOL Wow64Process = FALSE;
	if (IsWow64Process( pi->hProcess, &Wow64Process ) == FALSE)
	{
		printf( "IsWow64Process failed (%d).\n", GetLastError() );
		return 0;
		//	第二种判断文件版本信息的方法，放弃
		//if (GetProcessImageFileNameA(pi->hProcess, strFile, sizeof(strFile)) == 0)
		//{
		//	printf( "GetProcessImageFileNameA failed (%d).\n", GetLastError() );
		//}
		//else
		//{
		//	printf( "GetProcessImageFileNameA success \n");
		//	GetFileVersionInfoSizeA()
		//	GetFileVersionInfo
		//}
	}
	else
	{
		printf( "IsWow64Process success \n");
	}
	if (Wow64Process == FALSE)
	{
		printf( "Dest Process Is x64 Process \n");
		return 0;
	}
	else
	{
		DWORD					dwDword;
		LPVOID					p;
		EntryPointStruct		eps;
		ShellCode				sc;
		ShellCode *				t;
		BYTE					code[8];
		printf( "Dest Process Is x86 Process \n");
		p = VirtualAllocEx(pi->hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (p == NULL)
		{
			printf("Alloc Dest Process Memory Error [%d]\n", GetLastError());
			return 0;
		}

		if (GetDestProcessEPInfor(pi, &eps) == 0)
		{
			return 0;
		}

		InitShellCode(&sc);
		t = ((ShellCode *)((DWORD)p + 0xE00));
		sc.move_esi_NUMBER = (DWORD)&(t->bufEPCode);
		sc.move_edi_NUMBER = eps.dwEntryPointAddressInProcess;
		sc.push_string_point = (DWORD)&(t->dll_path);
		sc.jmp_NUMBER = eps.dwEntryPointAddressInProcess - (DWORD)&(t->jmp) - 5;
		sc.move_eax_NUMBER = (DWORD)LoadLibraryA;
		memcpy(sc.bufEPCode, eps.byteEntryPointCode, 5);
		strcpy_s(sc.dll_path, sizeof(sc.dll_path), dll_path);

		WriteProcessMemory(pi->hProcess, (char *)p + 0xE00, &sc, sizeof(sc), NULL);

		code[0] = 0xE9;
		*(DWORD*)&(code[1]) = (DWORD)p + 0xE00 - eps.dwEntryPointAddressInProcess - 5;
		WriteProcessMemory(pi->hProcess, (LPVOID)eps.dwEntryPointAddressInProcess, code, 5, NULL);

		VirtualProtectEx(pi->hProcess, (LPVOID)eps.dwEntryPointAddressInProcess, 5 , PAGE_EXECUTE_READWRITE, &dwDword);
	}

	return 1;
}

int CreateProcessSuppendA(char *exe_path, PROCESS_INFORMATION *pi)
{
	STARTUPINFOA si;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( pi, sizeof(*pi) );

	// Start the child process. 
	if( !CreateProcessA( NULL,   // No module name (use command line)
		exe_path,       // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_SUSPENDED,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		pi )           // Pointer to PROCESS_INFORMATION structure
		) 
	{
		printf( "CreateProcess failed (%d).\n", GetLastError() );
		return 0;
	}
	return 1;
}

int ResumeProcessThread(PROCESS_INFORMATION *pi)
{
	int nRet = 1;
	if ((DWORD)-1 == ResumeThread(pi->hThread))
	{
		printf( "ResumeThread failed (%d).\n", GetLastError() );
		nRet = 0;
	}
	
	CloseHandle(pi->hProcess);
	CloseHandle(pi->hThread);

	return nRet;
}


int main(int argc ,char **argv)
{
	char exe_path[260] = "";
	char dll_path[260] = "";
	PROCESS_INFORMATION pi;

	__asm
	{
	}
	if( argc != 3 )
	{
		printf("Usage: %s [exe_path] [dll_path]\n", argv[0]);
		return 1;
	}

	strcpy_s(exe_path, sizeof(exe_path), argv[1]);
	if (CreateProcessSuppendA(exe_path, &pi) == 0)
	{
		printf("Usage: %s [exe_path] [dll_path]\n\tCreateProcessError\n", argv[0]);
		return 2;
	}
	strcpy_s(dll_path, sizeof(dll_path), argv[2]);

	if (InjectDllToProcess(dll_path, &pi) == 0)
	{
		printf("Usage: %s [exe_path] [dll_path]\n\tInjectProcessError\n", argv[0]);
	}
	else
	{
		printf("Usage: %s [exe_path] [dll_path]\n\tInjectProcessSuccess\n", argv[0]);
	}

	if (ResumeProcessThread(&pi) == 0)
	{
		printf("Usage: %s [exe_path] [dll_path]\n\tResumeThreadError\n", argv[0]);
		return 3;
	}

	return 0;
}

