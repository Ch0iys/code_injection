/*
* BoB 5기 취약점 분석 트랙 최용선
* Code Injection 과제
*/
#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <process.h>
#include <tchar.h>

// CreateFile
typedef HANDLE(WINAPI *PFCREATEFILE)
(
	LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);

// WriteFile
typedef BOOL(WINAPI *PFWRITEFILE)
(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

// CloseHandle
typedef BOOL(WINAPI *PFCLOSEHANDLE)
(
	HANDLE hObject
);

// LoadLibraryA
typedef HMODULE(WINAPI *PFLOADLIBRARYA)
(
	LPCSTR lpLibFileName
);

// GetProcAddress
typedef FARPROC(WINAPI *PFGETPROCADDRESS)
(
	HMODULE hModule,
	LPCSTR lpProcName
);

// inject 구조체(인자값 전달) 선언
typedef struct _inject{
	FARPROC hFunc[4];
	char buf[4][100];
	wchar_t msg[2][100];
	int ret;
}INJECT, *PINJECT;

DWORD WINAPI Code_Injection(INJECT *lParam);
void tempFunction();

int main(int argc, char *argv[]) {
	PROCESS_INFORMATION pi = { 0, };
	STARTUPINFO si = { 0, };
	wchar_t path[] = L"calc.exe";
	HANDLE hHandle, hThread;
	// injection 시킬 함수의 크기 구하기
	DWORD dwBufSize = (DWORD)tempFunction - (DWORD)Code_Injection;
	LPVOID Virtual_Addr, Data_Addr;
	INJECT inject;
	HMODULE hMod;

	// LoadLibraryA와 GetProcAddress의 주소 가져오기
	hMod = GetModuleHandleA(("kernel32.dll"));
	inject.hFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
	inject.hFunc[1] = GetProcAddress(hMod, "GetProcAddress");

	// inject 구조체에 값 입력
	inject.msg[0][0] = 'h';
	inject.msg[0][1] = 'e';
	inject.msg[0][2] = 'l';
	inject.msg[0][3] = 'l';
	inject.msg[0][4] = 'o';
	inject.msg[0][5] = ' ';
	inject.msg[0][6] = 'w';
	inject.msg[0][7] = 'o';
	inject.msg[0][8] = 'r';
	inject.msg[0][9] = 'l';
	inject.msg[0][10] = 'd';
	inject.msg[0][11] = '!';
	inject.msg[0][12] = '\0';
	strcpy_s(inject.buf[0], "kernel32.dll");
	strcpy_s(inject.buf[1], "WriteFile");
	strcpy_s(inject.buf[2], "CreateFileW");
	strcpy_s(inject.buf[3], "CloseHandle");
	inject.msg[1][0] = 'h';
	inject.msg[1][1] = 'e';
	inject.msg[1][2] = 'l';
	inject.msg[1][3] = 'l';
	inject.msg[1][4] = 'o';
	inject.msg[1][5] = '.';
	inject.msg[1][6] = 't';
	inject.msg[1][7] = 'x';
	inject.msg[1][8] = 't';
	inject.msg[1][9] = '\0';

	si.cb = sizeof(si);

	// calc.exe 프로세스 오픈
	if (!(CreateProcess(NULL, path, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))) {
		printf("Can't open calc process.\n");
		exit(0);
	}

	Sleep(100);

	// calc.exe의 핸들 값 구하기
	if (!(hHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pi.dwProcessId))) {
		printf("Can't get handle of calc");
		exit(0);
	}

	// calc.exe에 인자의 크기만큼 가상 메모리 할당
	if (!(Data_Addr = VirtualAllocEx(hHandle, NULL, sizeof(INJECT), MEM_COMMIT, PAGE_READWRITE))){
		printf("Can't allocate virtual memory(arg).");
		exit(0);
	}

	// 할당한 가상 메모리에 인자의 내용 쓰기
	if (!(WriteProcessMemory(hHandle, Data_Addr, (LPCVOID)&inject, sizeof(INJECT), NULL))){
		printf("Can't write thread in calc.exe(arg).");
		exit(0);
	}

	// calc.exe에 함수의 크기만큼 가상 메모리 할당
	if (!(Virtual_Addr = VirtualAllocEx(hHandle, NULL, dwBufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
		printf("Can't allocate virtual memory.\n");
		exit(0);
	}

	// 할당한 가상 메모리에 함수의 내용 쓰기
	if (!WriteProcessMemory(hHandle, Virtual_Addr, (LPCVOID)Code_Injection, dwBufSize, NULL)) {
		printf("Can't write thread in calc.exe.\n");
		exit(0);
	}

	// 쓰레드 실행
	if (!(hThread = CreateRemoteThread(hHandle, NULL, 0, (LPTHREAD_START_ROUTINE)Virtual_Addr, Data_Addr, 0, NULL))) {
		printf("Can't get handle of thread.\n");
		exit(0);
	}
	//	hThread = (HANDLE)_beginthreadex(NULL, 0, (_beginthreadex_proc_type)Code_Injection, NULL, 0, (unsigned int *)&dwBufSize);

	printf("Create thread... OK\n");

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hHandle);

	return 0;
}

/*
* Code_Injection
* lParam : inject 구조체 인자로 전달
*
* pinject : lParam 지역변수로 저장
* hMod : kernel32.dll 모듈 호출
* hFile : CreateFile 결과 값(핸들) 저장
* pFunc, pFunc2, pFunc3 : WriteFile, CreateFile, CloseHandle 함수 주소 저장
* 
*/

DWORD WINAPI Code_Injection(INJECT *lParam) {
	PINJECT pinject = (PINJECT)lParam;
	HMODULE hMod = NULL;
	HANDLE hFile;
	FARPROC pFunc, pFunc2, pFunc3;

	// kernel32.dll LOAD
	hMod = ((PFLOADLIBRARYA)pinject->hFunc[0]) (pinject->buf[0]);

	// WriteFile, CreateFile, CloseFile 함수 주소 저장
	pFunc = (FARPROC)((PFGETPROCADDRESS)pinject->hFunc[1])(hMod, pinject->buf[1]);
	pFunc2 = (FARPROC)((PFGETPROCADDRESS)pinject->hFunc[1])(hMod, pinject->buf[2]);
	pFunc3 = (FARPROC)((PFGETPROCADDRESS)pinject->hFunc[1])(hMod, pinject->buf[3]);

	// CreateFile, WriteFile, CloseFile 함수 호출
	hFile = ((PFCREATEFILE)pFunc2)(pinject->msg[1], (GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_ALWAYS, 0, NULL);
	((PFWRITEFILE)pFunc)(hFile, pinject->msg[0], sizeof(TCHAR)*12, (LPDWORD)&pinject->ret, NULL);
	((PFCLOSEHANDLE)pFunc3)(hFile);

	return 0;
}


/*
* tempFunction
* Code_Injection 함수 크기를 구하기 위한 임시 함수
*/
void tempFunction() {

}
