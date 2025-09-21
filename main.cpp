#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <sddl.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <wintrust.h>
#include <winternl.h>
#include <wtsapi32.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Wtsapi32.lib")
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef ProcessCommandLineInformation
#define ProcessCommandLineInformation static_cast<PROCESSINFOCLASS>(60)
#endif

namespace {

using NtQueryInformationProcessFn = NTSTATUS(NTAPI *)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn ResolveNtQueryInformationProcess() {
  static NtQueryInformationProcessFn fn = []() {
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    if (!module) {
      return static_cast<NtQueryInformationProcessFn>(nullptr);
    }
    FARPROC proc = GetProcAddress(module, "NtQueryInformationProcess");
    if (!proc) {
      return static_cast<NtQueryInformationProcessFn>(nullptr);
    }
    NtQueryInformationProcessFn local = nullptr;
    std::memcpy(&local, &proc, sizeof(local));
    return local;
  }();
  return fn;
}

std::string ToUtf8(const std::wstring &input) {
  if (input.empty()) {
    return std::string();
  }
  int required = WideCharToMultiByte(CP_UTF8, 0, input.c_str(),
                                     static_cast<int>(input.size()), nullptr, 0,
                                     nullptr, nullptr);
  if (required <= 0) {
    return std::string();
  }
  std::string output(static_cast<size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()),
                      output.data(), required, nullptr, nullptr);
  return output;
}

std::wstring FileTimeToRFC3339(const FILETIME &filetime) {
  SYSTEMTIME utc_system{};
  if (!FileTimeToSystemTime(&filetime, &utc_system)) {
    return L"";
  }
  wchar_t buffer[64] = {};
  if (swprintf(buffer, std::size(buffer),
               L"%04u-%02u-%02uT%02u:%02u:%02uZ", utc_system.wYear,
               utc_system.wMonth, utc_system.wDay, utc_system.wHour,
               utc_system.wMinute, utc_system.wSecond) < 0) {
    return L"";
  }
  return buffer;
}

std::wstring CollapseSpaces(const std::wstring &input) {
  std::wstring result;
  bool previousSpace = false;
  bool insideQuotes = false;
  for (wchar_t ch : input) {
    if (ch == L'"') {
      insideQuotes = !insideQuotes;
      previousSpace = false;
      result.push_back(ch);
      continue;
    }
    if (!insideQuotes && ch == L' ') {
      if (!previousSpace) {
        result.push_back(ch);
        previousSpace = true;
      }
    } else {
      previousSpace = false;
      result.push_back(ch);
    }
  }
  return result;
}

std::wstring DescribeArchitecture(HANDLE process) {
  USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
  USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

  using IsWow64Process2Fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
  static IsWow64Process2Fn isWow64Process2 = []() {
    HMODULE module = GetModuleHandleW(L"kernel32.dll");
    if (!module) {
      return static_cast<IsWow64Process2Fn>(nullptr);
    }
    FARPROC proc = GetProcAddress(module, "IsWow64Process2");
    if (!proc) {
      return static_cast<IsWow64Process2Fn>(nullptr);
    }
    IsWow64Process2Fn local = nullptr;
    std::memcpy(&local, &proc, sizeof(local));
    return local;
  }();

  auto describeMachine = [](USHORT machine) -> std::wstring {
    switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64:
      return L"x64";
    case IMAGE_FILE_MACHINE_I386:
      return L"x86";
    case IMAGE_FILE_MACHINE_ARM64:
      return L"ARM64";
    case IMAGE_FILE_MACHINE_ARMNT:
      return L"ARM32";
    case IMAGE_FILE_MACHINE_UNKNOWN:
      return L"unknown";
    default: {
      std::wstringstream oss;
      oss << L"0x" << std::hex << std::setw(4) << std::setfill(L'0')
          << machine;
      return oss.str();
    }
    }
  };

  if (isWow64Process2) {
    if (isWow64Process2(process, &processMachine, &nativeMachine)) {
      std::wstring description = describeMachine(processMachine);
      if (processMachine != nativeMachine &&
          nativeMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
        description += L" (host:";
        description += describeMachine(nativeMachine);
        description += L")";
      }
      return description;
    }
  } else {
    BOOL isWow64 = FALSE;
    if (IsWow64Process(process, &isWow64)) {
      SYSTEM_INFO info{};
      GetNativeSystemInfo(&info);
      if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        return L"x86";
      }
      return isWow64 ? L"x86 on x64" : L"x64";
    }
  }
  return L"unknown";
}

bool GetProcessCreationTime(HANDLE process, std::wstring &time_string) {
  FILETIME creation{}, exit_time{}, kernel{}, user{};
  if (!GetProcessTimes(process, &creation, &exit_time, &kernel, &user)) {
    return false;
  }
  time_string = FileTimeToRFC3339(creation);
  return !time_string.empty();
}

bool GetProcessCommandLine(HANDLE process, std::wstring &command_line) {
  auto fn = ResolveNtQueryInformationProcess();
  if (!fn) {
    return false;
  }
  ULONG needed = 0;
  NTSTATUS status = fn(process, ProcessCommandLineInformation, nullptr, 0, &needed);
  if (status != STATUS_INFO_LENGTH_MISMATCH) {
    return false;
  }
  std::vector<std::byte> buffer(needed);
  status = fn(process, ProcessCommandLineInformation, buffer.data(), needed,
              &needed);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  auto unicode = reinterpret_cast<PUNICODE_STRING>(buffer.data());
  if (!unicode || !unicode->Buffer) {
    return false;
  }
  command_line.assign(unicode->Buffer,
                      unicode->Buffer + unicode->Length / sizeof(WCHAR));
  return true;
}

std::wstring LookupSid(PSID sid) {
  if (!IsValidSid(sid)) {
    return L"";
  }
  WCHAR name[256];
  WCHAR domain[256];
  DWORD name_size = std::size(name);
  DWORD domain_size = std::size(domain);
  SID_NAME_USE use = SidTypeUnknown;
  if (LookupAccountSidW(nullptr, sid, name, &name_size, domain, &domain_size,
                        &use)) {
    std::wstring result;
    if (domain_size > 0) {
      result.assign(domain, domain + domain_size);
      result.push_back(L'\\');
    }
    result.append(name, name + name_size);
    return result;
  }
  return L"";
}

std::wstring DescribeIntegrityLevel(const std::wstring &sid_string) {
  if (sid_string.find(L"S-1-16-12288") != std::wstring::npos) {
    return L"System";
  }
  if (sid_string.find(L"S-1-16-16384") != std::wstring::npos) {
    return L"Protected";
  }
  if (sid_string.find(L"S-1-16-8192") != std::wstring::npos) {
    return L"High";
  }
  if (sid_string.find(L"S-1-16-4096") != std::wstring::npos) {
    return L"Medium";
  }
  if (sid_string.find(L"S-1-16-2048") != std::wstring::npos) {
    return L"Low";
  }
  if (sid_string.find(L"S-1-16-0") != std::wstring::npos) {
    return L"Untrusted";
  }
  return L"Unknown";
}

std::wstring SidToString(PSID sid) {
  LPWSTR sid_string = nullptr;
  if (!ConvertSidToStringSidW(sid, &sid_string)) {
    return L"";
  }
  std::wstring result(sid_string);
  LocalFree(sid_string);
  return result;
}

struct PrivilegeInfo {
  std::wstring name;
  bool enabled = false;
};

std::vector<PrivilegeInfo> GetPrivileges(HANDLE token) {
  DWORD needed = 0;
  GetTokenInformation(token, TokenPrivileges, nullptr, 0, &needed);
  if (!needed) {
    return {};
  }
  std::vector<BYTE> buffer(needed);
  if (!GetTokenInformation(token, TokenPrivileges, buffer.data(), needed,
                           &needed)) {
    return {};
  }
  auto privileges =
      reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());
  std::vector<PrivilegeInfo> results;
  for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
    LUID luid = privileges->Privileges[i].Luid;
    WCHAR name[256];
    DWORD name_len = std::size(name);
    if (LookupPrivilegeNameW(nullptr, &luid, name, &name_len)) {
      bool enabled = (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
      results.push_back({std::wstring(name, name + name_len), enabled});
    }
  }
  return results;
}

struct TokenDiagnostics {
  bool isElevated = false;
  std::wstring logonUser;
  std::wstring integritySid;
  std::wstring integrityLevel;
  TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
  bool virtualizationAllowed = false;
  bool virtualizationEnabled = false;
  DWORD sessionId = 0;
  std::vector<PrivilegeInfo> privileges;
};

TokenDiagnostics AnalyzeToken(HANDLE process) {
  TokenDiagnostics diag;
  HANDLE token = nullptr;
  if (!OpenProcessToken(process,
                        TOKEN_QUERY | TOKEN_QUERY_SOURCE,
                        &token)) {
    return diag;
  }

  TOKEN_ELEVATION elevation{};
  DWORD len = sizeof(elevation);
  if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation),
                          &len)) {
    diag.isElevated = elevation.TokenIsElevated != 0;
  }

  TOKEN_ELEVATION_TYPE elevationType{};
  len = sizeof(elevationType);
  if (GetTokenInformation(token, TokenElevationType, &elevationType,
                          sizeof(elevationType), &len)) {
    diag.elevationType = elevationType;
  }

  DWORD virtualization = 0;
  len = sizeof(virtualization);
  if (GetTokenInformation(token, TokenVirtualizationAllowed, &virtualization,
                          sizeof(virtualization), &len)) {
    diag.virtualizationAllowed = virtualization != 0;
  }
  if (GetTokenInformation(token, TokenVirtualizationEnabled, &virtualization,
                          sizeof(virtualization), &len)) {
    diag.virtualizationEnabled = virtualization != 0;
  }

  DWORD sessionId = 0;
  len = sizeof(sessionId);
  if (GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId),
                          &len)) {
    diag.sessionId = sessionId;
  }

  DWORD needed = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
  if (needed) {
    std::vector<BYTE> buffer(needed);
    if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
      auto tokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
      diag.logonUser = LookupSid(tokenUser->User.Sid);
    }
  }

  needed = 0;
  GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &needed);
  if (needed) {
    std::vector<BYTE> buffer(needed);
    if (GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), needed,
                            &needed)) {
      auto label = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());
      diag.integritySid = SidToString(label->Label.Sid);
      diag.integrityLevel = DescribeIntegrityLevel(diag.integritySid);
    }
  }

  diag.privileges = GetPrivileges(token);

  CloseHandle(token);
  return diag;
}

std::wstring DescribeElevationType(TOKEN_ELEVATION_TYPE type) {
  switch (type) {
  case TokenElevationTypeDefault:
    return L"Default";
  case TokenElevationTypeFull:
    return L"Elevated";
  case TokenElevationTypeLimited:
    return L"Limited";
  default:
    return L"Unknown";
  }
}

std::wstring WtsConnectStateToString(WTS_CONNECTSTATE_CLASS state) {
  switch (state) {
  case WTSActive:
    return L"Active";
  case WTSConnected:
    return L"Connected";
  case WTSConnectQuery:
    return L"ConnectQuery";
  case WTSShadow:
    return L"Shadow";
  case WTSDisconnected:
    return L"Disconnected";
  case WTSIdle:
    return L"Idle";
  case WTSListen:
    return L"Listen";
  case WTSReset:
    return L"Reset";
  case WTSDown:
    return L"Down";
  case WTSInit:
    return L"Init";
  default:
    return L"Unknown";
  }
}

struct SessionDiagnostics {
  DWORD sessionId = 0;
  std::wstring stationName;
  std::wstring desktopName;
  std::wstring connectionState;
  std::wstring userName;
  bool interactive = false;
};

SessionDiagnostics AnalyzeSession(const TokenDiagnostics &tokenDiag) {
  SessionDiagnostics session;
  session.sessionId = tokenDiag.sessionId;

  LPWSTR buffer = nullptr;
  DWORD bytes = 0;
  if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                  tokenDiag.sessionId, WTSUserName, &buffer,
                                  &bytes) && buffer) {
    session.userName.assign(buffer, buffer + wcslen(buffer));
    WTSFreeMemory(buffer);
  }

  if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                  tokenDiag.sessionId, WTSConnectState, &buffer,
                                  &bytes) && buffer) {
    auto state = reinterpret_cast<WTS_CONNECTSTATE_CLASS *>(buffer);
    session.connectionState = WtsConnectStateToString(*state);
    WTSFreeMemory(buffer);
  }

  HWINSTA winsta = GetProcessWindowStation();
  if (winsta) {
    WCHAR name[256];
    DWORD needed = 0;
    if (GetUserObjectInformationW(winsta, UOI_NAME, name, sizeof(name),
                                  &needed)) {
      session.stationName.assign(name, name + wcslen(name));
    }
  }

  HDESK desk = GetThreadDesktop(GetCurrentThreadId());
  if (desk) {
    WCHAR name[256];
    DWORD needed = 0;
    if (GetUserObjectInformationW(desk, UOI_NAME, name, sizeof(name),
                                  &needed)) {
      session.desktopName.assign(name, name + wcslen(name));
    }
  }

  session.interactive = !session.stationName.empty() && !session.desktopName.empty();
  return session;
}

std::wstring DefaultSaveFileName() {
  SYSTEMTIME local{};
  GetLocalTime(&local);
  wchar_t buffer[32];
  int written = swprintf(buffer, std::size(buffer), L"%04u%02u%02u-%02u%02u%02u.txt",
                         local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute,
                         local.wSecond);
  if (written < 0) {
    return L"report.txt";
  }
  return buffer;
}

std::wstring DescribeSignatureStatus(LONG status) {
  switch (status) {
  case ERROR_SUCCESS:
    return L"Trusted";
  case TRUST_E_NOSIGNATURE:
    return L"Unsigned";
  case TRUST_E_EXPLICIT_DISTRUST:
    return L"Explicit distrust";
  case TRUST_E_SUBJECT_NOT_TRUSTED:
    return L"Subject not trusted";
  case CRYPT_E_SECURITY_SETTINGS:
    return L"Security settings prevent trust";
  default:
    return L"Error: " + std::to_wstring(status);
  }
}

std::optional<LONG> CheckSignature(const std::wstring &path) {
  if (path.empty()) {
    return std::nullopt;
  }

  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  fileInfo.pcwszFilePath = path.c_str();

  WINTRUST_DATA data{};
  data.cbStruct = sizeof(data);
  data.dwUIChoice = WTD_UI_NONE;
  data.dwStateAction = WTD_STATEACTION_VERIFY;
  data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  data.dwUnionChoice = WTD_CHOICE_FILE;
  data.pFile = &fileInfo;
  data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;

  GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = WinVerifyTrust(nullptr, &policyGUID, &data);

  WINTRUST_DATA closeData = data;
  closeData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policyGUID, &closeData);

  return status;
}

struct ProcessDiagnostics {
  DWORD pid = 0;
  DWORD ppid = 0;
  std::wstring exeName;
  std::wstring imagePath;
  std::wstring creationTime;
  std::wstring commandLine;
  std::wstring architecture;
  std::optional<LONG> signatureStatus;
};

std::optional<ProcessDiagnostics> DescribeProcess(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ |
                                   SYNCHRONIZE,
                               FALSE, pid);
  if (!process) {
    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
                          FALSE, pid);
  }
  if (!process) {
    return std::nullopt;
  }

  ProcessDiagnostics diag;
  diag.pid = pid;

  std::wstring image;
  image.resize(MAX_PATH);
  DWORD size = MAX_PATH;
  if (QueryFullProcessImageNameW(process, 0, image.data(), &size)) {
    image.resize(size);
  } else if (GetModuleFileNameExW(process, nullptr, image.data(), MAX_PATH)) {
    image.resize(wcslen(image.c_str()));
  } else {
    image.clear();
  }
  diag.imagePath = image;
  if (!image.empty()) {
    size_t pos = image.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos + 1 < image.size()) {
      diag.exeName = image.substr(pos + 1);
    } else {
      diag.exeName = image;
    }
  }

  GetProcessCreationTime(process, diag.creationTime);
  GetProcessCommandLine(process, diag.commandLine);
  diag.architecture = DescribeArchitecture(process);
  diag.signatureStatus = CheckSignature(diag.imagePath);

  CloseHandle(process);
  return diag;
}

std::unordered_map<DWORD, PROCESSENTRY32W> SnapshotProcesses() {
  std::unordered_map<DWORD, PROCESSENTRY32W> table;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return table;
  }
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      table.emplace(entry.th32ProcessID, entry);
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return table;
}

std::vector<ProcessDiagnostics> BuildAncestry(DWORD pid, size_t depth = 3) {
  std::vector<ProcessDiagnostics> chain;
  auto processes = SnapshotProcesses();
  DWORD current = pid;
  for (size_t i = 0; i < depth; ++i) {
    auto diag = DescribeProcess(current);
    if (!diag) {
      break;
    }
    auto it = processes.find(current);
    if (it != processes.end()) {
      diag->ppid = it->second.th32ParentProcessID;
    }
    chain.push_back(*diag);
    if (!diag->ppid || diag->ppid == current) {
      break;
    }
    current = diag->ppid;
  }
  return chain;
}

struct EnvironmentSummary {
  std::wstring currentDirectory;
  std::map<std::wstring, std::wstring> selected;
  std::uint64_t hash = 0;
};

template <typename Container>
std::uint64_t Fnv1aHash(const Container &data) {
  const std::uint64_t prime = 1099511628211ull;
  std::uint64_t hash = 1469598103934665603ull;
  for (auto ch : data) {
    hash ^= static_cast<std::uint64_t>(ch);
    hash *= prime;
  }
  return hash;
}

EnvironmentSummary SummarizeEnvironment() {
  EnvironmentSummary summary;
  DWORD needed = GetCurrentDirectoryW(0, nullptr);
  if (needed) {
    std::wstring buffer(needed, L'\0');
    if (GetCurrentDirectoryW(needed, buffer.data())) {
      if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
      }
      summary.currentDirectory = buffer;
    }
  }

  const std::array<const wchar_t *, 6> keys = {
      L"PATH", L"PATHEXT", L"TEMP", L"SYSTEMROOT", L"USERPROFILE", L"APPDATA"};
  for (const auto *key : keys) {
    DWORD size = GetEnvironmentVariableW(key, nullptr, 0);
    if (!size) {
      continue;
    }
    std::wstring value(size, L'\0');
    if (GetEnvironmentVariableW(key, value.data(), size)) {
      if (!value.empty() && value.back() == L'\0') {
        value.pop_back();
      }
      summary.selected.emplace(key, value);
    }
  }

  std::wstring aggregate;
  for (const auto &kv : summary.selected) {
    aggregate.append(kv.first);
    aggregate.push_back(L'=');
    aggregate.append(kv.second);
  }
  summary.hash = Fnv1aHash(aggregate);
  return summary;
}

struct StdHandles {
  bool stdInRedirected = false;
  bool stdOutRedirected = false;
  bool stdErrRedirected = false;
};

StdHandles DetectStdHandles() {
  StdHandles handles;
  auto isRedirected = [](DWORD handleType) {
    HANDLE handle = GetStdHandle(handleType);
    if (!handle || handle == INVALID_HANDLE_VALUE) {
      return true;
    }
    DWORD type = GetFileType(handle);
    return type != FILE_TYPE_CHAR;
  };
  handles.stdInRedirected = isRedirected(STD_INPUT_HANDLE);
  handles.stdOutRedirected = isRedirected(STD_OUTPUT_HANDLE);
  handles.stdErrRedirected = isRedirected(STD_ERROR_HANDLE);
  return handles;
}


std::wstring BuildHashString(std::uint64_t value) {
  std::wostringstream oss;
  oss << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << value;
  return oss.str();
}

std::wstring BuildTextReport(const std::vector<std::wstring> &argv,
                             const std::vector<ProcessDiagnostics> &chain,
                             const TokenDiagnostics &token,
                             const SessionDiagnostics &session,
                             const EnvironmentSummary &env,
                             const StdHandles &handles) {
  std::wostringstream out;
  out << L"Command line raw: " << CollapseSpaces(GetCommandLineW()) << L"\n";
  out << L"Arguments (argv):\n";
  for (size_t i = 0; i < argv.size(); ++i) {
    out << L"  [" << i << L"] " << argv[i] << L"\n";
  }
  out << L"\n";

  for (size_t i = 0; i < chain.size(); ++i) {
    const auto &proc = chain[i];
    out << L"Process level " << i << L"\n";
    out << L"  PID: " << proc.pid << L"\n";
    out << L"  PPID: " << proc.ppid << L"\n";
    out << L"  Executable: " << proc.exeName << L"\n";
    out << L"  Image path: " << proc.imagePath << L"\n";
    out << L"  Created: " << proc.creationTime << L"\n";
    out << L"  Architecture: " << proc.architecture << L"\n";
    if (proc.signatureStatus) {
      out << L"  Signature: "
          << DescribeSignatureStatus(*proc.signatureStatus) << L"\n";
    }
    if (!proc.commandLine.empty()) {
      out << L"  Command line: " << CollapseSpaces(proc.commandLine) << L"\n";
    }
    out << L"\n";
  }

  out << L"Token\n";
  out << L"  User: " << token.logonUser << L"\n";
  out << L"  Elevated: " << (token.isElevated ? L"yes" : L"no") << L"\n";
  out << L"  Elevation type: " << DescribeElevationType(token.elevationType)
      << L"\n";
  out << L"  Integrity SID: " << token.integritySid << L"\n";
  out << L"  Integrity level: " << token.integrityLevel << L"\n";
  out << L"  Virtualization allowed: "
      << (token.virtualizationAllowed ? L"yes" : L"no") << L"\n";
  out << L"  Virtualization enabled: "
      << (token.virtualizationEnabled ? L"yes" : L"no") << L"\n";
  out << L"  Privileges:\n";
  for (const auto &priv : token.privileges) {
    out << L"    - " << priv.name
        << (priv.enabled ? L" (enabled)" : L" (disabled)") << L"\n";
  }
  out << L"\n";

  out << L"Session\n";
  out << L"  Session ID: " << session.sessionId << L"\n";
  out << L"  Connection state: " << session.connectionState << L"\n";
  out << L"  Window station: " << session.stationName << L"\n";
  out << L"  Desktop: " << session.desktopName << L"\n";
  out << L"  Interactive: " << (session.interactive ? L"yes" : L"no") << L"\n";
  out << L"  User: " << session.userName << L"\n";
  out << L"\n";

  out << L"Environment\n";
  out << L"  Current directory: " << env.currentDirectory << L"\n";
  out << L"  Selected variables:\n";
  for (const auto &kv : env.selected) {
    out << L"    " << kv.first << L"=" << kv.second << L"\n";
  }
  out << L"  Combined hash (fnv1a-64): " << BuildHashString(env.hash) << L"\n";
  out << L"\n";

  out << L"I/O\n";
  out << L"  stdin redirected: " << (handles.stdInRedirected ? L"yes" : L"no")
      << L"\n";
  out << L"  stdout redirected: " << (handles.stdOutRedirected ? L"yes" : L"no")
      << L"\n";
  out << L"  stderr redirected: " << (handles.stdErrRedirected ? L"yes" : L"no")
      << L"\n";

  out << L"\n";
  return out.str();
}



bool WriteToFile(const std::wstring &path, const std::wstring &content) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  std::string utf8 = ToUtf8(content);
  DWORD written = 0;
  bool ok = true;
  if (!utf8.empty()) {
    if (!WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written,
                   nullptr)) {
      ok = false;
    }
  }
  CloseHandle(file);
  return ok;
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  std::vector<std::wstring> args;
  args.reserve(static_cast<size_t>(argc));
  for (int i = 0; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  auto chain = BuildAncestry(GetCurrentProcessId(), 4);
  TokenDiagnostics tokenDiag = AnalyzeToken(GetCurrentProcess());
  SessionDiagnostics sessionDiag = AnalyzeSession(tokenDiag);
  EnvironmentSummary env = SummarizeEnvironment();
  StdHandles handles = DetectStdHandles();

  std::wstring output = BuildTextReport(args, chain, tokenDiag, sessionDiag,
                                           env, handles);

  std::wcout << output;

  std::wstring target = DefaultSaveFileName();
  if (!WriteToFile(target, output)) {
    std::wcerr << L"Failed to save report: " << target << L"\n";
  } else {
    std::wcout << L"Saved report to: " << target << L"\n";
  }

  std::wcout << L"Press any key to exit." << std::flush;
  std::wstring dummy;
  std::getline(std::wcin, dummy);

  return 0;
}


#else

#include <iostream>

int main() {
  std::cerr << "This utility is intended for Windows builds only." << std::endl;
  return 1;
}

#endif
