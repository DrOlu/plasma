// plasma-tap.cpp — Plasma's ETW tap for the "gap providers".
//
// Fills the sensory slot Sysmon/WHIDS do not own: PowerShell (full ETW
// fidelity, not just channel 4104), WMI-Activity, DNS-Client, .NET Runtime
// (narrow keywords), Schannel. Built on Microsoft's krabsetw (MIT).
//
// Lake-less by construction:
//   * everything is scored in memory against a fixed rules file;
//   * only MATCHES are written (JSONL), capped by --max-matches;
//   * raw stream counts go to stderr as heartbeats and die with the process;
//   * no service, no persistence — runs on demand for --for seconds
//     (or until Ctrl+C) and exits.
//
// Matching is deterministic: provider + event id + case-insensitive
// substring on one named field (or event name when field is empty, or all
// parsed fields when field is "*"). Empty substring = match-all for that
// provider+id.
//
// Rules file format (one rule per line, 7 pipe-separated fields; lines
// starting with '#' are comments):
//   name|provider|event_id|field|substr|severity|technique
//
// Admin required to open a trace session (StartTrace); the tap reports
// failure as JSON on stdout and exits 3 rather than pretending.
//
// Build (MSVC x64):
//   cl /nologo /std:c++17 /EHsc /O2 /W3 /I <krabsetw>/krabs plasma-tap.cpp ^
//      /Fe:plasma-tap.exe tdh.lib advapi32.lib

#include "krabs.hpp"

#include <windows.h>
#include <tdh.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// provider catalog: alias -> full ETW provider name (TDH resolves the GUID)
// ---------------------------------------------------------------------------

std::wstring CanonicalProvider(const std::wstring& alias) {
    if (alias == L"powershell") return L"Microsoft-Windows-PowerShell";
    if (alias == L"wmi") return L"Microsoft-Windows-WMI-Activity";
    if (alias == L"dns") return L"Microsoft-Windows-DNS-Client";
    if (alias == L"dotnet") return L"Microsoft-Windows-DotNETRuntime";
    if (alias == L"schannel") return L"Microsoft-Windows-Schannel";
    return alias;  // full names pass straight through
}

unsigned long long KeywordsFor(const std::wstring& canonical) {
    // .NET Runtime at "all keywords, verbose" is hundreds of events/second;
    // a narrow mask (Loader | Security) keeps it useful without a firehose.
    if (canonical == L"Microsoft-Windows-DotNETRuntime") return 0x400000000002ULL;
    return 0xFFFFFFFFFFFFFFFFULL;
}

bool GuidFromName(const std::wstring& name, GUID* out) {
    ULONG size = 0;
    if (TdhEnumerateProviders(nullptr, &size) != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return false;
    }
    std::vector<BYTE> buf(size);
    PPROVIDER_ENUMERATION_INFO info =
        reinterpret_cast<PPROVIDER_ENUMERATION_INFO>(buf.data());
    if (TdhEnumerateProviders(info, &size) != ERROR_SUCCESS) return false;
    for (ULONG i = 0; i < info->NumberOfProviders; ++i) {
        const TRACE_PROVIDER_INFO& p = info->TraceProviderInfoArray[i];
        const wchar_t* pn = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<BYTE*>(info) + p.ProviderNameOffset);
        if (_wcsicmp(pn, name.c_str()) == 0) { *out = p.ProviderGuid; return true; }
    }
    return false;
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

struct Rule {
    std::wstring name;
    std::wstring provider;      // canonical full name or L"*"
    unsigned long event_id;     // 0 = any
    std::wstring field;         // L"" -> event name, L"*" -> all fields
    std::wstring needle;        // case-insensitive substring; L"" = match-all
    std::wstring severity;
    std::wstring technique;
};

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

bool ContainsCI(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    return Lower(haystack).find(Lower(needle)) != std::wstring::npos;
}

std::vector<std::wstring> Split(const std::wstring& line, wchar_t sep) {
    std::vector<std::wstring> parts;
    std::wstring cur;
    for (wchar_t c : line) {
        if (c == sep) { parts.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    parts.push_back(cur);
    return parts;
}

bool LoadRules(const std::string& path, std::vector<Rule>& rules, std::string* err) {
    std::ifstream in(path);
    if (!in) { *err = "cannot open rules file: " + path; return false; }
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        if (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::wstring> t;
        // widen via narrow→wide (rules are ASCII)
        for (const auto& part : Split(std::wstring(line.begin(), line.end()), L'|')) t.push_back(part);
        if (t.size() != 7) { *err = "rule line " + std::to_string(lineno) + ": expected 7 fields"; return false; }
        Rule r;
        r.name = t[0];
        r.provider = CanonicalProvider(Lower(t[1]));
        r.event_id = static_cast<unsigned long>(_wtol(t[2].c_str()));
        r.field = t[3];
        r.needle = t[4];
        r.severity = Lower(t[5]);
        r.technique = t[6];
        rules.push_back(r);
    }
    return true;
}

// ---------------------------------------------------------------------------
// output helpers
// ---------------------------------------------------------------------------

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        &s[0], n, nullptr, nullptr);
    return s;
}

void JsonEscape(const std::wstring& in, std::string& out) {
    out.push_back('"');
    char hex[8];
    for (wchar_t wc : in) {
        unsigned char c = static_cast<unsigned char>(wc);
        if (wc == L'"') out += "\\\"";
        else if (wc == L'\\') out += "\\\\";
        else if (wc == L'\n') out += "\\n";
        else if (wc == L'\r') out += "\\r";
        else if (wc == L'\t') out += "\\t";
        else if (c < 0x20) { snprintf(hex, sizeof(hex), "\\u%04x", c); out += hex; }
        else {
            // encode wchar as UTF-8 (BMP only; surrogates are rare in our fields)
            if (wc < 0x80) out.push_back(static_cast<char>(wc));
            else if (wc < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (wc >> 6)));
                out.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
            } else {
                out.push_back(static_cast<char>(0xE0 | (wc >> 12)));
                out.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
            }
        }
    }
    out.push_back('"');
}

std::string IsoFromFT(const LARGE_INTEGER& li) {
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;      // same 8-byte layout, different union
    ft.dwHighDateTime = li.HighPart;    // spelling across SDK headers
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[40];
    snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             st.wMilliseconds);
    return buf;
}

const size_t kFieldCap = 400;

std::wstring Clip(const std::wstring& v) {
    return v.size() > kFieldCap ? v.substr(0, kFieldCap) : v;
}

std::wstring ToWide(const std::string& s) {
    return std::wstring(s.begin(), s.end());  // argv is ASCII in our use
}

// ---------------------------------------------------------------------------
// shared collection state
// ---------------------------------------------------------------------------

struct Stats {
    std::atomic<unsigned long long> events{0};
    std::atomic<unsigned long long> matches{0};
    std::atomic<bool> overflow{false};
    std::mutex file_mutex;
};

// fields worth carrying from any of our providers (try each event, keep hits)
const wchar_t* kFieldCandidates[] = {
    L"ScriptBlockText", L"ScriptBlockId", L"Path", L"Message",
    L"CommandLine", L"HostName", L"HostApplication",
    L"QueryName", L"QueryType", L"QueryResults",
    L"NamespaceName", L"Query", L"Operation", L"ProviderName", L"ClientMachine",
    L"ProcessName", L"NewProcessName", L"Application", L"FileName",
    L"TargetUserName", L"SubjectUserName",
};

std::wstring ParseStringField(krabs::parser& parser, const wchar_t* field) {
    try {
        return Clip(parser.parse<std::wstring>(field));
    } catch (...) {
        try {
            std::string a = parser.parse<std::string>(field);
            int n = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), nullptr, 0);
            std::wstring w(static_cast<size_t>(n), 0);
            MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), &w[0], n);
            return Clip(w);
        } catch (...) {
            return L"";
        }
    }
}

}  // namespace

// console-ctrl bridge so Ctrl+C ends the session cleanly
static std::atomic<krabs::user_trace*> g_trace{nullptr};
static BOOL WINAPI CtrlHandler(DWORD type) {
    (void)type;
    krabs::user_trace* t = g_trace.load();
    if (t) { try { t->stop(); } catch (...) {} }
    return TRUE;
}

int main(int argc, char** argv) {
    std::string rules_path, out_path = "plasma-tap-matches.jsonl";
    std::wstring providers_csv = L"powershell,wmi,dns";
    std::wstring session = L"PlasmaTap";
    unsigned long for_seconds = 0;
    unsigned long max_matches = 500;
    bool selftest = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--rules") rules_path = next();
        else if (a == "--out") out_path = next();
        else if (a == "--providers") providers_csv = ToWide(next());
        else if (a == "--for") for_seconds = strtoul(next().c_str(), nullptr, 10);
        else if (a == "--max-matches") max_matches = strtoul(next().c_str(), nullptr, 10);
        else if (a == "--session") session = ToWide(next());
        else if (a == "--selftest") selftest = true;
        else { fprintf(stderr, "unknown arg %s\n", a.c_str()); return 2; }
    }

    std::vector<Rule> rules;
    std::string err;
    if (!LoadRules(rules_path, rules, &err)) {
        printf("{\"ok\":false,\"error\":\"%s\"}\n", err.c_str());
        return 2;
    }

    if (selftest) {
        // no trace is opened; validates the rules + build, prints catalog
        printf("{\"ok\":true,\"rules\":%zu,\"mode\":\"selftest\"}\n", rules.size());
        return 0;
    }

    // resolve requested providers
    std::vector<std::wstring> requested;
    for (const auto& tok : Split(providers_csv, L',')) {
        if (!tok.empty()) requested.push_back(CanonicalProvider(Lower(tok)));
    }

    krabs::user_trace trace(session);
    g_trace.store(&trace);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    Stats stats;
    std::vector<std::unique_ptr<krabs::provider<>>> providers;
    std::vector<std::wstring> enabled, unresolved;

    for (const auto& canonical : requested) {
        GUID g;
        if (!GuidFromName(canonical, &g)) { unresolved.push_back(canonical); continue; }
        auto p = std::make_unique<krabs::provider<>>(g);
        p->any(KeywordsFor(canonical));
        p->add_on_event_callback([&](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
            try {
                stats.events++;
                krabs::schema schema(record, ctx.schema_locator);
                unsigned id = schema.event_id();
                std::wstring pname = schema.provider_name();
                std::wstring ename = schema.event_name();

                // parse candidate fields once per event
                krabs::parser parser(schema);
                std::vector<std::pair<std::wstring, std::wstring>> props;
                for (const wchar_t* f : kFieldCandidates) {
                    std::wstring v = ParseStringField(parser, f);
                    if (!v.empty()) props.emplace_back(f, v);
                }

                // deterministic match pass
                const Rule* hit = nullptr;
                std::wstring hit_field, hit_value;
                for (const Rule& r : rules) {
                    if (r.provider != L"*" && Lower(r.provider) != Lower(pname)) continue;
                    if (r.event_id != 0 && r.event_id != id) continue;
                    if (r.field.empty()) {
                        if (ContainsCI(ename, r.needle)) { hit = &r; hit_field = L"event_name"; hit_value = ename; break; }
                    } else if (r.field == L"*") {
                        for (const auto& kv : props) {
                            if (ContainsCI(kv.second, r.needle)) { hit = &r; hit_field = kv.first; hit_value = kv.second; break; }
                        }
                        if (hit) break;
                    } else {
                        for (const auto& kv : props) {
                            if (_wcsicmp(kv.first.c_str(), r.field.c_str()) == 0 &&
                                ContainsCI(kv.second, r.needle)) {
                                hit = &r; hit_field = kv.first; hit_value = kv.second; break;
                            }
                        }
                        if (hit) break;
                    }
                }
                if (!hit) return;
                if (stats.matches >= max_matches) { stats.overflow = true; return; }

                std::ostringstream line;
                line << "{\"ts\":\"" << IsoFromFT(schema.timestamp()) << "\""
                     << ",\"provider\":\"" << Utf8(pname) << "\""
                     << ",\"event_id\":" << id
                     << ",\"event_name\":\"" << Utf8(ename) << "\""
                     << ",\"pid\":" << schema.process_id()
                     << ",\"rule\":\"" << Utf8(hit->name) << "\""
                     << ",\"severity\":\"" << Utf8(hit->severity) << "\""
                     << ",\"technique\":\"" << Utf8(hit->technique) << "\""
                     << ",\"field\":\"" << Utf8(hit_field) << "\"";
                line << ",\"snippet\":";
                std::string esc;
                JsonEscape(Clip(hit_value), esc);
                line << esc;
                line << ",\"props\":{";
                bool first = true;
                for (const auto& kv : props) {
                    if (!first) line << ",";
                    first = false;
                    std::string kesc;
                    JsonEscape(kv.first, kesc);
                    std::string vesc;
                    JsonEscape(kv.second, vesc);
                    line << kesc << ":" << vesc;
                }
                line << "}}";

                std::lock_guard<std::mutex> lock(stats.file_mutex);
                std::ofstream out(out_path, std::ios::app);
                out << line.str() << "\n";
                stats.matches++;
            } catch (...) {
                // a malformed event must never take the tap down
            }
        });
        providers.push_back(std::move(p));
        trace.enable(*providers.back());
        enabled.push_back(canonical);
    }

    if (enabled.empty()) {
        printf("{\"ok\":false,\"error\":\"no providers resolved\",\"unresolved\":%zu}\n",
               unresolved.size());
        return 3;
    }

    // duration window
    std::thread stopper;
    if (for_seconds > 0) {
        stopper = std::thread([for_seconds]() {
            std::this_thread::sleep_for(std::chrono::seconds(for_seconds));
            krabs::user_trace* t = g_trace.load();
            if (t) { try { t->stop(); } catch (...) {} }
        });
    }

    int rc = 0;
    try {
        trace.process();
    } catch (const std::exception& e) {
        printf("{\"ok\":false,\"error\":\"trace failed: %s\"}\n", e.what());
        rc = 3;
    } catch (...) {
        printf("{\"ok\":false,\"error\":\"trace failed (unknown)\"}\n");
        rc = 3;
    }
    if (stopper.joinable()) stopper.join();

    // final summary: counts only — the raw stream dies here
    printf("{\"ok\":true,\"events_seen\":%llu,\"matches\":%llu,"
           "\"overflow\":%s,\"providers\":%zu,\"rules\":%zu}\n",
           stats.events.load(), stats.matches.load(),
           stats.overflow.load() ? "true" : "false", enabled.size(), rules.size());
    return rc;
}
