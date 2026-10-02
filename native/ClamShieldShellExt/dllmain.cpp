#include <windows.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <new>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

// Must match sparse-package AppxManifest.xml.
// {69DCC69B-7670-49C2-AF27-D1902DB70252}
static const CLSID CLSID_ClamShieldExplorerCommand =
{ 0x69dcc69b, 0x7670, 0x49c2, { 0xaf, 0x27, 0xd1, 0x90, 0x2d, 0xb7, 0x02, 0x52 } };

#ifndef RETURN_IF_FAILED
#define RETURN_IF_FAILED(hrExpr) do { const HRESULT _hr = (hrExpr); if (FAILED(_hr)) return _hr; } while (0)
#endif

enum class CommandAction {
    Root,
    ClamAv,
    ClamAvYara,
    ClamAvYaraVirusTotal,
    AddException
};

struct MenuState {
    bool enabled = false;
    bool yaraAvailable = false;
    bool virusTotalAvailable = false;
};

static HINSTANCE g_instance = nullptr;
static long g_objectCount = 0;

static std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return value;
}

static bool ContainsJsonTrue(const std::wstring& content, const wchar_t* key) {
    const std::wstring lowered = ToLower(content);
    const std::wstring pattern = std::wstring(L"\"") + ToLower(key) + L"\"";
    const size_t pos = lowered.find(pattern);
    if (pos == std::wstring::npos) return false;
    const size_t colon = lowered.find(L":", pos + pattern.size());
    if (colon == std::wstring::npos) return false;
    const size_t value = lowered.find_first_not_of(L" \t\r\n", colon + 1);
    return value != std::wstring::npos && lowered.compare(value, 4, L"true") == 0;
}

static std::wstring ReadTextFile(const std::wstring& filePath) {
    std::wifstream stream(filePath);
    if (!stream) return L"";
    std::wstringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

static std::wstring ProgramDataPath(const wchar_t* relativePath) {
    wchar_t programData[MAX_PATH] = {};
    DWORD length = GetEnvironmentVariableW(L"ProgramData", programData, ARRAYSIZE(programData));
    std::wstring root = length > 0 ? std::wstring(programData, length) : L"C:\\ProgramData";
    if (!root.empty() && root.back() != L'\\') root += L"\\";
    return root + L"ClamShield\\" + relativePath;
}

static MenuState ReadMenuState() {
    const std::wstring content = ReadTextFile(ProgramDataPath(L"windows-context-menu.json"));
    MenuState state;
    state.enabled = ContainsJsonTrue(content, L"enabled");
    state.yaraAvailable = ContainsJsonTrue(content, L"yaraAvailable");
    state.virusTotalAvailable = ContainsJsonTrue(content, L"virusTotalAvailable");
    return state;
}

static LPWSTR AllocShellString(const wchar_t* value) {
    const size_t bytes = (wcslen(value) + 1) * sizeof(wchar_t);
    auto* result = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
    if (!result) return nullptr;
    memcpy(result, value, bytes);
    return result;
}

static bool ActionVisible(CommandAction action, const MenuState& state) {
    if (!state.enabled) return false;
    if (action == CommandAction::ClamAvYara) return state.yaraAvailable;
    if (action == CommandAction::ClamAvYaraVirusTotal) return state.yaraAvailable && state.virusTotalAvailable;
    return true;
}

static const wchar_t* ActionTitle(CommandAction action) {
    switch (action) {
    case CommandAction::Root: return L"ClamShield";
    case CommandAction::ClamAv: return L"Scan with ClamAV only";
    case CommandAction::ClamAvYara: return L"Scan with ClamAV + YARA";
    case CommandAction::ClamAvYaraVirusTotal: return L"Scan with ClamAV + YARA + VirusTotal";
    case CommandAction::AddException: return L"Add to ClamShield exceptions";
    default: return L"ClamShield";
    }
}

static const wchar_t* ActionId(CommandAction action) {
    switch (action) {
    case CommandAction::ClamAvYara: return L"clamav-yara";
    case CommandAction::ClamAvYaraVirusTotal: return L"clamav-yara-vt";
    case CommandAction::AddException: return L"add-exception";
    case CommandAction::ClamAv:
    default: return L"clamav";
    }
}

static std::wstring JsonEscape(const std::wstring& value) {
    std::wstring result;
    result.reserve(value.size() + 8);
    for (wchar_t ch : value) {
        if (ch == L'\\' || ch == L'"') {
            result += L'\\';
            result += ch;
        } else if (ch == L'\r') {
            result += L"\\r";
        } else if (ch == L'\n') {
            result += L"\\n";
        } else {
            result += ch;
        }
    }
    return result;
}

static HRESULT CollectShellItemPaths(IShellItemArray* items, std::vector<std::wstring>& paths) {
    if (!items) return E_INVALIDARG;
    DWORD count = 0;
    RETURN_IF_FAILED(items->GetCount(&count));
    for (DWORD index = 0; index < count; ++index) {
        IShellItem* item = nullptr;
        if (FAILED(items->GetItemAt(index, &item)) || !item) continue;
        PWSTR itemPath = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &itemPath)) && itemPath && itemPath[0]) {
            paths.emplace_back(itemPath);
        }
        CoTaskMemFree(itemPath);
        item->Release();
    }
    return paths.empty() ? E_INVALIDARG : S_OK;
}

static std::wstring ModuleDirectory() {
    wchar_t modulePath[MAX_PATH] = {};
    GetModuleFileNameW(g_instance, modulePath, ARRAYSIZE(modulePath));
    PathRemoveFileSpecW(modulePath);
    return modulePath;
}

static std::wstring InstallDirectory() {
    std::wstring directory = ModuleDirectory();
    wchar_t fileName[MAX_PATH] = {};
    wcscpy_s(fileName, PathFindFileNameW(directory.c_str()));
    if (_wcsicmp(fileName, L"shell") == 0) {
        PathRemoveFileSpecW(directory.data());
        directory.resize(wcslen(directory.c_str()));
    }
    return directory;
}

static HRESULT WriteRequestFile(CommandAction action, const std::vector<std::wstring>& paths, std::wstring& requestPath) {
    wchar_t tempPath[MAX_PATH] = {};
    if (!GetTempPathW(ARRAYSIZE(tempPath), tempPath)) return HRESULT_FROM_WIN32(GetLastError());
    std::wstring folder = std::wstring(tempPath) + L"ClamShield";
    CreateDirectoryW(folder.c_str(), nullptr);

    GUID id = {};
    RETURN_IF_FAILED(CoCreateGuid(&id));
    wchar_t guidText[64] = {};
    StringFromGUID2(id, guidText, ARRAYSIZE(guidText));
    requestPath = folder + L"\\context-menu-" + guidText + L".json";

    std::wofstream stream(requestPath, std::ios::trunc);
    if (!stream) return HRESULT_FROM_WIN32(GetLastError());
    stream << L"{\"action\":\"" << ActionId(action) << L"\",\"paths\":[";
    for (size_t index = 0; index < paths.size(); ++index) {
        if (index > 0) stream << L",";
        stream << L"\"" << JsonEscape(paths[index]) << L"\"";
    }
    stream << L"]}";
    return S_OK;
}

static HRESULT InvokeClamShield(CommandAction action, IShellItemArray* items) {
    std::vector<std::wstring> paths;
    RETURN_IF_FAILED(CollectShellItemPaths(items, paths));

    std::wstring requestPath;
    RETURN_IF_FAILED(WriteRequestFile(action, paths, requestPath));

    const std::wstring installDir = InstallDirectory();
    const std::wstring exePath = installDir + L"\\ClamShield.exe";
    const std::wstring parameters = L"--context-menu-request \"" + requestPath + L"\"";
    HINSTANCE result = ShellExecuteW(nullptr, L"open", exePath.c_str(), parameters.c_str(), installDir.c_str(), SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        return HRESULT_FROM_WIN32(static_cast<DWORD>(reinterpret_cast<INT_PTR>(result)));
    }
    return S_OK;
}

class ExplorerCommand;

class ExplorerCommandEnum final : public IEnumExplorerCommand {
public:
    explicit ExplorerCommandEnum(const std::vector<IExplorerCommand*>& commands) : commands_(commands) {
        InterlockedIncrement(&g_objectCount);
        for (auto* command : commands_) if (command) command->AddRef();
    }

    ~ExplorerCommandEnum() {
        for (auto* command : commands_) if (command) command->Release();
        InterlockedDecrement(&g_objectCount);
    }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IEnumExplorerCommand) {
            *ppv = static_cast<IEnumExplorerCommand*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refCount_); }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG count = InterlockedDecrement(&refCount_);
        if (count == 0) delete this;
        return count;
    }

    IFACEMETHODIMP Next(ULONG celt, IExplorerCommand** pUICommand, ULONG* pceltFetched) override {
        if (!pUICommand) return E_POINTER;
        ULONG fetched = 0;
        while (fetched < celt && index_ < commands_.size()) {
            pUICommand[fetched] = commands_[index_++];
            pUICommand[fetched]->AddRef();
            ++fetched;
        }
        if (pceltFetched) *pceltFetched = fetched;
        return fetched == celt ? S_OK : S_FALSE;
    }

    IFACEMETHODIMP Skip(ULONG celt) override {
        index_ = min(commands_.size(), index_ + celt);
        return index_ < commands_.size() ? S_OK : S_FALSE;
    }

    IFACEMETHODIMP Reset() override {
        index_ = 0;
        return S_OK;
    }

    IFACEMETHODIMP Clone(IEnumExplorerCommand** ppenum) override {
        if (!ppenum) return E_POINTER;
        auto* clone = new (std::nothrow) ExplorerCommandEnum(commands_);
        if (!clone) return E_OUTOFMEMORY;
        clone->index_ = index_;
        *ppenum = clone;
        return S_OK;
    }

private:
    long refCount_ = 1;
    std::vector<IExplorerCommand*> commands_;
    size_t index_ = 0;
};

class ExplorerCommand final : public IExplorerCommand {
public:
    explicit ExplorerCommand(CommandAction action) : action_(action) {
        InterlockedIncrement(&g_objectCount);
    }

    ~ExplorerCommand() {
        InterlockedDecrement(&g_objectCount);
    }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IExplorerCommand) {
            *ppv = static_cast<IExplorerCommand*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refCount_); }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG count = InterlockedDecrement(&refCount_);
        if (count == 0) delete this;
        return count;
    }

    IFACEMETHODIMP GetTitle(IShellItemArray*, LPWSTR* ppszName) override {
        if (!ppszName) return E_POINTER;
        *ppszName = AllocShellString(ActionTitle(action_));
        return *ppszName ? S_OK : E_OUTOFMEMORY;
    }

    IFACEMETHODIMP GetIcon(IShellItemArray*, LPWSTR* ppszIcon) override {
        if (!ppszIcon) return E_POINTER;
        const std::wstring iconPath = InstallDirectory() + L"\\ClamShield.exe";
        *ppszIcon = AllocShellString(iconPath.c_str());
        return *ppszIcon ? S_OK : E_OUTOFMEMORY;
    }

    IFACEMETHODIMP GetToolTip(IShellItemArray*, LPWSTR* ppszInfotip) override {
        if (!ppszInfotip) return E_POINTER;
        *ppszInfotip = nullptr;
        return E_NOTIMPL;
    }

    IFACEMETHODIMP GetCanonicalName(GUID* pguidCommandName) override {
        if (!pguidCommandName) return E_POINTER;
        *pguidCommandName = CLSID_ClamShieldExplorerCommand;
        return S_OK;
    }

    IFACEMETHODIMP GetState(IShellItemArray* items, BOOL, EXPCMDSTATE* pCmdState) override {
        if (!pCmdState) return E_POINTER;
        const MenuState state = ReadMenuState();
        if (!ActionVisible(action_, state)) {
            *pCmdState = ECS_HIDDEN;
            return S_OK;
        }
        if (action_ != CommandAction::Root) {
            DWORD count = 0;
            if (!items || FAILED(items->GetCount(&count)) || count == 0) {
                *pCmdState = ECS_HIDDEN;
                return S_OK;
            }
        }
        *pCmdState = ECS_ENABLED;
        return S_OK;
    }

    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) override {
        if (action_ == CommandAction::Root) return S_FALSE;
        return InvokeClamShield(action_, items);
    }

    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* pFlags) override {
        if (!pFlags) return E_POINTER;
        *pFlags = action_ == CommandAction::Root ? ECF_HASSUBCOMMANDS : ECF_DEFAULT;
        return S_OK;
    }

    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;
        if (action_ != CommandAction::Root) return E_NOTIMPL;

        const MenuState state = ReadMenuState();
        std::vector<IExplorerCommand*> commands;
        const CommandAction actions[] = {
            CommandAction::ClamAv,
            CommandAction::ClamAvYara,
            CommandAction::ClamAvYaraVirusTotal,
            CommandAction::AddException
        };
        for (CommandAction action : actions) {
            if (!ActionVisible(action, state)) continue;
            auto* command = new (std::nothrow) ExplorerCommand(action);
            if (!command) {
                for (auto* item : commands) item->Release();
                return E_OUTOFMEMORY;
            }
            commands.push_back(command);
        }
        auto* result = new (std::nothrow) ExplorerCommandEnum(commands);
        for (auto* command : commands) command->Release();
        if (!result) return E_OUTOFMEMORY;
        *ppEnum = result;
        return S_OK;
    }

private:
    long refCount_ = 1;
    CommandAction action_;
};

class ClassFactory final : public IClassFactory {
public:
    ClassFactory() { InterlockedIncrement(&g_objectCount); }
    ~ClassFactory() { InterlockedDecrement(&g_objectCount); }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refCount_); }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG count = InterlockedDecrement(&refCount_);
        if (count == 0) delete this;
        return count;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* command = new (std::nothrow) ExplorerCommand(CommandAction::Root);
        if (!command) return E_OUTOFMEMORY;
        const HRESULT hr = command->QueryInterface(riid, ppv);
        command->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_objectCount);
        else InterlockedDecrement(&g_objectCount);
        return S_OK;
    }

private:
    long refCount_ = 1;
};

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid != CLSID_ClamShieldExplorerCommand) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) ClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return g_objectCount == 0 ? S_OK : S_FALSE;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
