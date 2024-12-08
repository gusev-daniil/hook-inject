#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <DbgHelp.h>
#include <Shlwapi.h>
#include <iostream>
#include <mutex>
#include <sddl.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")

static std::wstring g_functionName;
static std::wstring g_hideFileName;
static std::wstring g_dllDirectory;

const std::wstring PIPE_NAME = L"\\\\.\\pipe\\MonitorPipe";
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;

// Типы функций для хуков
typedef HANDLE(WINAPI* PFN_CREATEFILEW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
    );
typedef HANDLE(WINAPI* PFN_FINDFIRSTFILEW)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* PFN_FINDNEXTFILEW)(HANDLE, LPWIN32_FIND_DATAW);

// Оригинальные функции
static PFN_CREATEFILEW     Real_CreateFileW = CreateFileW;
static PFN_FINDFIRSTFILEW  Real_FindFirstFileW = FindFirstFileW;
static PFN_FINDNEXTFILEW   Real_FindNextFileW = FindNextFileW;

std::mutex g_pipeMutex;
std::mutex g_consoleMutex;

// Функция для отправки сообщений в пайп
void SendMessageToPipe(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(g_pipeMutex);

    if (g_hPipe == INVALID_HANDLE_VALUE) {
        while (true) {
            g_hPipe = CreateFileW(
                PIPE_NAME.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            if (g_hPipe != INVALID_HANDLE_VALUE)
                break;

            DWORD error = GetLastError();
            if (error != ERROR_PIPE_BUSY) {
                std::lock_guard<std::mutex> lockConsole(g_consoleMutex);
                std::wcerr << L"[PIPE ERROR] Failed to connect to named pipe. Error: " << error << std::endl;
                return;
            }

            if (!WaitNamedPipeW(PIPE_NAME.c_str(), 20000)) {
                std::lock_guard<std::mutex> lockConsole(g_consoleMutex);
                std::wcerr << L"[PIPE ERROR] WaitNamedPipeW timed out." << std::endl;
                return;
            }
        }
    }

    DWORD bytesWritten;
    std::wstring msgWithNewline = message + L"\n";
    BOOL success = WriteFile(
        g_hPipe,
        msgWithNewline.c_str(),
        static_cast<DWORD>(msgWithNewline.size() * sizeof(wchar_t)),
        &bytesWritten,
        NULL
    );

    if (!success || bytesWritten == 0) {
        DWORD error = GetLastError();
        std::lock_guard<std::mutex> lockConsole(g_consoleMutex);
        std::wcerr << L"[PIPE ERROR] WriteFile failed. Error: " << error << std::endl;
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

// Функция для получения директории DLL
void GetDllDirectoryPath(HMODULE hModule) {
    wchar_t dllPath[MAX_PATH];
    if (GetModuleFileNameW(hModule, dllPath, MAX_PATH) == 0) {
        GetCurrentDirectoryW(MAX_PATH, dllPath);
    }
    PathRemoveFileSpecW(dllPath);
    g_dllDirectory = dllPath;
}

// Функция для инициализации логирования (только через пайп)
bool InitializeLogging() {
    SendMessageToPipe(L"[INIT] Logging initialized.");
    return true;
}

// Функция для логирования сообщений
void LogMessage(const wchar_t* format, ...) {
    wchar_t buffer[512];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
    va_end(args);

    time_t now = time(0);
    struct tm tstruct;
    wchar_t timeStr[100];
    localtime_s(&tstruct, &now);
    wcsftime(timeStr, sizeof(timeStr), L"%Y-%m-%d %X", &tstruct);

    std::wstring finalMessage = L"[" + std::wstring(timeStr) + L"] " + buffer;

    SendMessageToPipe(finalMessage);
}

// Хук для CreateFileW
static HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    LogMessage(L"[HOOK] CreateFileW | File: %s", lpFileName);

    if (!g_hideFileName.empty() && _wcsicmp(lpFileName, g_hideFileName.c_str()) == 0) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Хук для FindFirstFileW
static HANDLE WINAPI Hooked_FindFirstFileW(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    LogMessage(L"[HOOK] FindFirstFileW | Pattern: %s", lpFileName);

    HANDLE hFind = Real_FindFirstFileW(lpFileName, lpFindFileData);
    if (hFind != INVALID_HANDLE_VALUE && !g_hideFileName.empty()) {
        if (_wcsicmp(lpFindFileData->cFileName, g_hideFileName.c_str()) == 0) {
            WIN32_FIND_DATAW nextData;
            BOOL bFound = Real_FindNextFileW(hFind, &nextData);
            if (!bFound) {
                FindClose(hFind);
                SetLastError(ERROR_FILE_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            else {
                *lpFindFileData = nextData;
            }
        }
    }
    return hFind;
}

// Хук для FindNextFileW
static BOOL WINAPI Hooked_FindNextFileW(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    BOOL result;
    do {
        result = Real_FindNextFileW(hFindFile, lpFindFileData);
        if (!result) break;
    } while (!g_hideFileName.empty() && _wcsicmp(lpFindFileData->cFileName, g_hideFileName.c_str()) == 0);

    if (result) {
        LogMessage(L"[HOOK] FindNextFileW | File: %s", lpFindFileData->cFileName);
    }

    return result;
}

// Функция для чтения параметров из shared memory
void ReadParametersFromSharedMemory() {
    // Используем локальное имя без "Global\\"
    HANDLE hMapFile = OpenFileMappingW(FILE_MAP_READ, FALSE, L"MonitorSharedMemory");
    if (hMapFile == NULL) {
        LogMessage(L"[ERROR] Failed to open shared memory. Error: %d", GetLastError());
        return;
    }

    LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 4096);
    if (!pBuf) {
        LogMessage(L"[ERROR] Failed to map view of shared memory. Error: %d", GetLastError());
        CloseHandle(hMapFile);
        return;
    }

    wchar_t params[2048];
    memcpy(params, pBuf, 4096);
    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile);

    std::wstring paramStr(params);
    size_t pos = paramStr.find(L"|");
    if (pos != std::wstring::npos) {
        g_functionName = paramStr.substr(0, pos);
        g_hideFileName = paramStr.substr(pos + 1);
    }
    else {
        g_functionName = paramStr;
    }

    LogMessage(L"[INIT] Parameters read from shared memory.");
    LogMessage(L"[INIT] Function to monitor: %s", g_functionName.c_str());
    LogMessage(L"[INIT] File to hide: %s", g_hideFileName.c_str());
}

// Функция для патчинга IAT
BOOL PatchIAT(HMODULE hModule, LPCSTR targetFuncName, LPVOID pNewFunc, LPVOID* pOriginalFunc) {
    if (!hModule) {
        LogMessage(L"[ERROR] PatchIAT failed: hModule is NULL.");
        return FALSE;
    }

    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

    if (!pImportDesc) {
        LogMessage(L"[ERROR] ImageDirectoryEntryToData failed for module.");
        return FALSE;
    }

    for (; pImportDesc->Name; pImportDesc++) {
        LPCSTR szModName = (LPCSTR)((PBYTE)hModule + pImportDesc->Name);
        HMODULE hImportMod = GetModuleHandleA(szModName);
        if (!hImportMod) {
            hImportMod = LoadLibraryA(szModName);
        }

        if (!hImportMod) {
            LogMessage(L"[ERROR] Failed to load module: %S", szModName);
            continue;
        }

        PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->FirstThunk);

        for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pFirstThunk++) {
            if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + pOriginalThunk->u1.AddressOfData);
            LPCSTR szFuncName = (LPCSTR)pImportByName->Name;

            if (_stricmp(szFuncName, targetFuncName) == 0) {
                DWORD oldProtect;
                if (VirtualProtect(&pFirstThunk->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &oldProtect)) {
                    *pOriginalFunc = (LPVOID)pFirstThunk->u1.Function;
                    pFirstThunk->u1.Function = (ULONG_PTR)pNewFunc;
                    VirtualProtect(&pFirstThunk->u1.Function, sizeof(LPVOID), oldProtect, &oldProtect);
                    LogMessage(L"[HOOK] Patched IAT for function: %S", szFuncName);
                    return TRUE;
                }
                else {
                    LogMessage(L"[ERROR] VirtualProtect failed for function: %S. Error: %d", szFuncName, GetLastError());
                }
            }
        }
    }

    if (_stricmp(targetFuncName, "FindNextFileW") == 0) {
        LogMessage(L"[WARN] Failed to patch IAT for function: %S (likely not imported)", targetFuncName);
    }
    else {
        LogMessage(L"[ERROR] Failed to patch IAT for function: %S", targetFuncName);
    }

    return FALSE;
}

// Функция для установки хуков на функции
BOOL HookFunctions() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        LogMessage(L"[ERROR] HookFunctions failed: GetModuleHandle returned NULL.");
        return FALSE;
    }

    bool hookCreate = (g_functionName.empty() || _wcsicmp(g_functionName.c_str(), L"CreateFileW") == 0);
    bool hookFindFirst = (g_functionName.empty() || _wcsicmp(g_functionName.c_str(), L"FindFirstFileW") == 0);
    bool hookFindNext = (g_functionName.empty() || _wcsicmp(g_functionName.c_str(), L"FindNextFileW") == 0);

    if (hookCreate) {
        if (PatchIAT(hModule, "CreateFileW", Hooked_CreateFileW, (LPVOID*)&Real_CreateFileW)) {
            LogMessage(L"[HOOK] Successfully hooked CreateFileW");
        }
        else {
            LogMessage(L"[HOOK] Failed to hook CreateFileW");
        }
    }

    if (hookFindFirst) {
        if (PatchIAT(hModule, "FindFirstFileW", Hooked_FindFirstFileW, (LPVOID*)&Real_FindFirstFileW)) {
            LogMessage(L"[HOOK] Successfully hooked FindFirstFileW");
        }
        else {
            LogMessage(L"[HOOK] Failed to hook FindFirstFileW");
        }
    }

    if (hookFindNext) {
        if (PatchIAT(hModule, "FindNextFileW", Hooked_FindNextFileW, (LPVOID*)&Real_FindNextFileW)) {
            LogMessage(L"[HOOK] Successfully hooked FindNextFileW");
        }
        else {
            LogMessage(L"[HOOK] Failed to hook FindNextFileW");
        }
    }

    return TRUE;
}

// Точка входа DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        {
            GetDllDirectoryPath(hModule);

            if (!InitializeLogging()) {
                // Если инициализация логирования не удалась, продолжить без неё
            }

            DWORD injectedPID = GetCurrentProcessId();
            LogMessage(L"[INIT] DLL injected into Process ID: %d", injectedPID);

            ReadParametersFromSharedMemory();
            HookFunctions();
        }
        break;
    case DLL_PROCESS_DETACH:
    {
        // Нет необходимости закрывать файлы, так как логирование в файл удалено
        // Закрываем пайп, если он открыт
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
    }
    break;
    }
    return TRUE;
}
