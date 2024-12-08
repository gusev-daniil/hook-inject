#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <sddl.h>
#include <cstring> // For memcpy

#pragma comment(lib, "advapi32.lib")

// Constants
const std::wstring PIPE_NAME = L"\\\\.\\pipe\\MonitorPipe";
const std::wstring SHARED_MEMORY_NAME = L"MonitorSharedMemory";
const size_t SHARED_MEMORY_SIZE = 4096;
const std::wstring DLL_NAME = L"MonitorHook.dll";

// RAII Wrapper for HANDLE
class HandleWrapper {
public:
    HandleWrapper(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
    ~HandleWrapper() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL) {
            CloseHandle(handle_);
        }
    }
    HANDLE get() const { return handle_; }
    void reset(HANDLE handle = INVALID_HANDLE_VALUE) {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }
    HANDLE release() {
        HANDLE temp = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return temp;
    }
    // Disable copy
    HandleWrapper(const HandleWrapper&) = delete;
    HandleWrapper& operator=(const HandleWrapper&) = delete;
    // Enable move
    HandleWrapper(HandleWrapper&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    HandleWrapper& operator=(HandleWrapper&& other) noexcept {
        if (this != &other) {
            reset(other.handle_);
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
private:
    HANDLE handle_;
};

// Class to handle argument parsing
class ArgumentParser {
public:
    ArgumentParser(int argc, wchar_t* argv[]) {
        parse(argc, argv);
    }

    bool isValid() const { return valid_; }
    void printUsage() const {
        std::wcout << L"Usage:\n"
            << L"  -pid <ProcessID>           Target process ID.\n"
            << L"  -name <ProcessName>        Target process name.\n"
            << L"  -func <FunctionName>       Function to monitor.\n"
            << L"  -hide <FileName>           File to hide.\n";
    }

    DWORD getTargetPID() const { return targetPID_; }
    const std::wstring& getFunctionName() const { return functionName_; }
    const std::wstring& getHideFileName() const { return hideFileName_; }

private:
    bool valid_ = false;
    DWORD targetPID_ = 0;
    std::wstring targetProcessName_;
    std::wstring functionName_;
    std::wstring hideFileName_;

    void parse(int argc, wchar_t* argv[]) {
        for (int i = 1; i < argc; ++i) {
            if (_wcsicmp(argv[i], L"-pid") == 0 && i + 1 < argc) {
                targetPID_ = _wtoi(argv[++i]);
            }
            else if (_wcsicmp(argv[i], L"-name") == 0 && i + 1 < argc) {
                targetProcessName_ = argv[++i];
            }
            else if (_wcsicmp(argv[i], L"-func") == 0 && i + 1 < argc) {
                functionName_ = argv[++i];
            }
            else if (_wcsicmp(argv[i], L"-hide") == 0 && i + 1 < argc) {
                hideFileName_ = argv[++i];
            }
            else {
                std::wcerr << L"Unknown or incomplete argument: " << argv[i] << std::endl;
                return;
            }
        }

        if (targetPID_ == 0 && targetProcessName_.empty()) {
            std::wcerr << L"Error: Target process not specified.\n";
            return;
        }

        if (functionName_.empty() && hideFileName_.empty()) {
            std::wcerr << L"Error: No function to monitor or file to hide specified.\n";
            return;
        }

        // If process name is provided, resolve PID
        if (!targetProcessName_.empty()) {
            targetPID_ = getProcessIdByName(targetProcessName_);
            if (targetPID_ == 0) {
                std::wcerr << L"Error: Process " << targetProcessName_ << L" not found.\n";
                return;
            }
        }

        valid_ = true;
    }

    DWORD getProcessIdByName(const std::wstring& processName) const {
        DWORD pid = 0;
        HandleWrapper snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snapshot.get() == INVALID_HANDLE_VALUE) {
            std::wcerr << L"CreateToolhelp32Snapshot failed (" << GetLastError() << L").\n";
            return 0;
        }

        PROCESSENTRY32W pe = { 0 };
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snapshot.get(), &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot.get(), &pe));
        }
        else {
            std::wcerr << L"Process32FirstW failed (" << GetLastError() << L").\n";
        }

        return pid;
    }
};

// Class to handle shared memory operations
class SharedMemory {
public:
    SharedMemory(const std::wstring& name, size_t size) : name_(name), size_(size) {}

    bool create() {
        SECURITY_ATTRIBUTES sa;
        PSECURITY_DESCRIPTOR pSD = nullptr;

        // Convert string security descriptor to allow full access to everyone
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;WD)",
            SDDL_REVISION_1,
            &pSD,
            nullptr))
        {
            std::wcerr << L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed ("
                << GetLastError() << L").\n";
            return false;
        }

        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;

        handle_.reset(CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            &sa,
            PAGE_READWRITE,
            0,
            static_cast<DWORD>(size_),
            name_.c_str()
        ));

        LocalFree(pSD);

        if (handle_.get() == nullptr || handle_.get() == INVALID_HANDLE_VALUE) {
            std::wcerr << L"CreateFileMappingW failed (" << GetLastError() << L").\n";
            return false;
        }

        return true;
    }

    bool write(const std::wstring& data) const {
        if (handle_.get() == nullptr || handle_.get() == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Shared memory handle is invalid.\n";
            return false;
        }

        LPVOID pBuf = MapViewOfFile(handle_.get(), FILE_MAP_ALL_ACCESS, 0, 0, size_);
        if (pBuf == nullptr) {
            std::wcerr << L"MapViewOfFile failed (" << GetLastError() << L").\n";
            return false;
        }

        // Prepare the data to write, separated by '|'
        std::wstring combined = data;
        size_t bytesToWrite = (combined.length() + 1) * sizeof(wchar_t);
        memcpy(pBuf, combined.c_str(), bytesToWrite);

        UnmapViewOfFile(pBuf);
        return true;
    }

private:
    std::wstring name_;
    size_t size_;
    HandleWrapper handle_;
};

// Class to handle DLL injection
class DLLInjector {
public:
    static bool inject(DWORD pid, const std::wstring& dllPath) {
        HandleWrapper hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
        if (hProcess.get() == nullptr) {
            std::wcerr << L"OpenProcess failed (" << GetLastError() << L").\n";
            return false;
        }

        size_t dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        LPVOID allocAddress = VirtualAllocEx(hProcess.get(), nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocAddress == nullptr) {
            std::wcerr << L"VirtualAllocEx failed (" << GetLastError() << L").\n";
            return false;
        }

        if (!WriteProcessMemory(hProcess.get(), allocAddress, dllPath.c_str(), dllPathSize, nullptr)) {
            std::wcerr << L"WriteProcessMemory failed (" << GetLastError() << L").\n";
            VirtualFreeEx(hProcess.get(), allocAddress, 0, MEM_RELEASE);
            return false;
        }

        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32 == nullptr) {
            std::wcerr << L"GetModuleHandleW failed (" << GetLastError() << L").\n";
            VirtualFreeEx(hProcess.get(), allocAddress, 0, MEM_RELEASE);
            return false;
        }

        LPVOID loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
        if (loadLibraryAddr == nullptr) {
            std::wcerr << L"GetProcAddress failed (" << GetLastError() << L").\n";
            VirtualFreeEx(hProcess.get(), allocAddress, 0, MEM_RELEASE);
            return false;
        }

        HandleWrapper hThread(CreateRemoteThread(hProcess.get(), nullptr, 0,
            (LPTHREAD_START_ROUTINE)loadLibraryAddr,
            allocAddress, 0, nullptr));
        if (hThread.get() == nullptr) {
            std::wcerr << L"CreateRemoteThread failed (" << GetLastError() << L").\n";
            VirtualFreeEx(hProcess.get(), allocAddress, 0, MEM_RELEASE);
            return false;
        }

        // Wait for the remote thread to complete
        WaitForSingleObject(hThread.get(), INFINITE);

        // Clean up
        VirtualFreeEx(hProcess.get(), allocAddress, 0, MEM_RELEASE);
        return true;
    }
};

// Class to handle Named Pipe communication
class PipeListener {
public:
    PipeListener(const std::wstring& pipeName, std::mutex& consoleMutex, std::atomic<bool>& running)
        : pipeName_(pipeName), consoleMutex_(consoleMutex), running_(running) {}

    void operator()() {
        SECURITY_ATTRIBUTES sa;
        PSECURITY_DESCRIPTOR pSD = nullptr;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;WD)",
            SDDL_REVISION_1,
            &pSD,
            nullptr))
        {
            std::lock_guard<std::mutex> lock(consoleMutex_);
            std::wcerr << L"Failed to convert security descriptor. Error: " << GetLastError() << std::endl;
            return;
        }

        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;

        pipeHandle_.reset(CreateNamedPipeW(
            pipeName_.c_str(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, // Max instances
            512,
            512,
            0,
            &sa
        ));

        LocalFree(pSD);

        if (pipeHandle_.get() == INVALID_HANDLE_VALUE) {
            std::lock_guard<std::mutex> lock(consoleMutex_);
            std::wcerr << L"Failed to create named pipe. Error: " << GetLastError() << std::endl;
            return;
        }

        // Attempt to connect
        BOOL connected = ConnectNamedPipe(pipeHandle_.get(), nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            std::lock_guard<std::mutex> lock(consoleMutex_);
            std::wcerr << L"Failed to connect to named pipe. Error: " << GetLastError() << std::endl;
            return;
        }

        wchar_t buffer[512] = { 0 };
        DWORD bytesRead = 0;

        while (running_ && ReadFile(pipeHandle_.get(), buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, nullptr)) {
            if (bytesRead == 0) break; // No more data

            buffer[bytesRead / sizeof(wchar_t)] = L'\0'; // Null-terminate

            {
                std::lock_guard<std::mutex> lock(consoleMutex_);
                std::wcout << buffer << std::endl;
            }
        }

        DisconnectNamedPipe(pipeHandle_.get());
    }

    // Method to close the pipe externally
    void closePipe() {
        pipeHandle_.reset(); // This will close the handle, unblocking ReadFile
    }

private:
    std::wstring pipeName_;
    std::mutex& consoleMutex_;
    std::atomic<bool>& running_;
    HandleWrapper pipeHandle_;
};


// Class to manage Shared Memory operations
class SharedMemoryManager {
public:
    SharedMemoryManager(const std::wstring& name, size_t size)
        : sharedMemory_(name, size) {}

    bool initialize(const std::wstring& functionName, const std::wstring& hideFileName) {
        if (!sharedMemory_.create()) {
            return false;
        }

        std::wstring data = functionName + L"|" + hideFileName;
        return sharedMemory_.write(data);
    }

private:
    SharedMemory sharedMemory_;
};

// Main Controller Class
class InjectorController {
public:
    InjectorController(int argc, wchar_t* argv[])
        : parser_(argc, argv),
        sharedMemoryManager_(SHARED_MEMORY_NAME, SHARED_MEMORY_SIZE),
        pipeListener_(PIPE_NAME, consoleMutex_, running_)
    {}

    int run() {
        if (!parser_.isValid()) {
            parser_.printUsage();
            return 1;
        }

        DWORD targetPID = parser_.getTargetPID();
        std::wcout << L"Target Process ID: " << targetPID << std::endl;

        if (!sharedMemoryManager_.initialize(parser_.getFunctionName(), parser_.getHideFileName())) {
            std::wcerr << L"Failed to initialize shared memory.\n";
            return 1;
        }

        // Start pipe listener thread
        std::thread listenerThread(std::ref(pipeListener_));

        // Get full path to DLL
        std::wstring dllPath = getFullDllPath();
        if (dllPath.empty()) {
            std::wcerr << L"Failed to get full path to DLL.\n";
            cleanup();
            return 1;
        }

        // Inject DLL
        if (!DLLInjector::inject(targetPID, dllPath)) {
            std::wcerr << L"DLL injection failed.\n";
            cleanup();
            return 1;
        }

        // Open target process for synchronization
        HandleWrapper hTargetProcess(OpenProcess(SYNCHRONIZE, FALSE, targetPID));
        if (hTargetProcess.get() == nullptr) {
            std::wcerr << L"Failed to open target process for synchronization ("
                << GetLastError() << L").\n";
            cleanup();
            return 1;
        }

        // Wait for the target process to terminate
        DWORD waitResult = WaitForSingleObject(hTargetProcess.get(), INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            std::wcout << L"Target process has terminated. Exiting...\n";
        }
        else {
            std::wcerr << L"WaitForSingleObject failed or was abandoned ("
                << GetLastError() << L").\n";
        }

        // Signal shutdown
        cleanup();

        // Wait for listener thread to finish
        if (listenerThread.joinable()) {
            listenerThread.join();
        }

        return 0;
    }

private:
    ArgumentParser parser_;
    SharedMemoryManager sharedMemoryManager_;
    PipeListener pipeListener_;
    std::mutex consoleMutex_;
    std::atomic<bool> running_{ true };

    std::wstring getFullDllPath() const {
        wchar_t pathBuffer[MAX_PATH] = { 0 };
        DWORD result = GetFullPathNameW(DLL_NAME.c_str(), MAX_PATH, pathBuffer, nullptr);
        if (result == 0 || result > MAX_PATH) {
            std::wcerr << L"GetFullPathNameW failed (" << GetLastError() << L").\n";
            return L"";
        }
        return std::wstring(pathBuffer);
    }

    void cleanup() {
        running_ = false;
        pipeListener_.closePipe(); // Ensure the pipe is closed to unblock ReadFile
    }
};

int wmain(int argc, wchar_t* argv[]) {
    InjectorController controller(argc, argv);
    return controller.run();
}
