#ifndef SYSLOGMANAGER_HPP
#define SYSLOGMANAGER_HPP

#include "connection.hpp"

#include <thread>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <algorithm>
#include <ctime>
#include <fmt/format.h>
#include <fmt/chrono.h>

namespace NDR
{
    namespace Util  
    {
        namespace Syslog
        {
            // 규격 준수를 위한 문자열 유틸리티
            class SyslogUtil {
            public:
                // CEF Header 전용 이스케이프: '|'와 '\' 처리
                static std::string EscapeHeader(const std::string& str) {
                    std::string out;
                    for (char c : str) {
                        if (c == '|' || c == '\\') out += '\\';
                        out += c;
                    }
                    return out;
                }

                // CEF Extension 전용 이스케이프: '=', '\', '\n', '\r' 처리
                static std::string EscapeExtension(const std::string& str) {
                    std::string out;
                    for (char c : str) {
                        if (c == '=' || c == '\\' || c == '\n' || c == '\r') out += '\\';
                        out += c;
                    }
                    return out;
                }

                // RFC5424 Header 필드용 (Hostname, AppName 등): 공백을 '_'로 치환
                static std::string SanitizeField(std::string str) {
                    if (str.empty()) return "-";
                    std::replace(str.begin(), str.end(), ' ', '_');
                    return str;
                }
            };

            struct CefMessage
            {
                int version = 0;
                std::string device_vendor;
                std::string device_product;
                std::string device_version;
                std::string signature_id;
                std::string name;
                int severity = 5;

                // 이미 이스케이프 처리가 완료된 extension 문자열
                std::string message; 

                std::string ToString() const
                {
                    // 헤더의 각 필드에 대해 이스케이프 적용 필수
                    return fmt::format(
                        "CEF:{}|{}|{}|{}|{}|{}|{}|{}",
                        version,
                        SyslogUtil::EscapeHeader(device_vendor),
                        SyslogUtil::EscapeHeader(device_product),
                        SyslogUtil::EscapeHeader(device_version),
                        SyslogUtil::EscapeHeader(signature_id),
                        SyslogUtil::EscapeHeader(name),
                        severity,
                        message
                    );
                }
            };  

            struct Rfc5424Header
            {   
                int facility = 16;        // local0
                int severity = 5;         

                std::string hostname;
                std::string app_name;
                std::string procid = "-";
                std::string msgid = "-";
                std::string timestamp;    // ISO8601

                int Pri() const { return facility * 8 + severity; }
            };

            struct Rfc5424Message
            {
                Rfc5424Header header;
                CefMessage msg;

                std::string ToString_in_CEF() const
                {
                    return fmt::format(
                        "<{}>1 {} {} {} {} {} - {}",
                        header.Pri(),
                        header.timestamp,
                        SyslogUtil::SanitizeField(header.hostname),
                        SyslogUtil::SanitizeField(header.app_name),
                        SyslogUtil::SanitizeField(header.procid),
                        SyslogUtil::SanitizeField(header.msgid),
                        msg.ToString()
                    );
                }
                
                std::string ToString_in_TEXT(const std::string& TEXT) const
                {
                    return fmt::format(
                        "<{}>1 {} {} {} {} {} - {}",
                        header.Pri(),
                        header.timestamp,
                        SyslogUtil::SanitizeField(header.hostname),
                        SyslogUtil::SanitizeField(header.app_name),
                        SyslogUtil::SanitizeField(header.procid),
                        SyslogUtil::SanitizeField(header.msgid),
                        TEXT
                    );
                }
            };

            class SyslogManager
            {
                std::string host;
                std::string app;
                std::string cef_vendor;
                std::string cef_product;
                std::string cef_version;

                std::map<std::string, std::shared_ptr<Connection::Connector>> connections;
                std::shared_ptr<std::mutex> mtx = nullptr;

            public:
                SyslogManager(
                    const std::string& hostname = "network-sensor",
                    const std::string& app_name = "network-sensor-app",
                    const std::string& vendor = "vatex",
                    const std::string& product = "vatex-network-sensor",
                    const std::string& version = "1.0-prototype"
                )
                    : host(hostname),
                    app(app_name),
                    cef_vendor(vendor),
                    cef_product(product),
                    cef_version(version)
                {
                    mtx = std::make_shared<std::mutex>();
                }

                ~SyslogManager()
                {
                    std::lock_guard<std::mutex> lock(*mtx);
                    for (auto& [_, conn] : connections)
                        conn->Disconnect();
                }

                // TEXT 모드 (RFC 5424 전용)
                bool SendEvent_with_TEXT_in_text(const std::string& text)
                {
                    return _SendEvent_in_TEXT(text);
                }

                bool SendEvent_with_flatten_json_in_text(const std::map<std::string, std::string>& exts)
                {
                    std::string flattened;
                    for (auto it = exts.begin(); it != exts.end(); ++it)
                    {
                        flattened += fmt::format("{}={}{}", it->first, SyslogUtil::EscapeExtension(it->second), 
                                     (std::next(it) == exts.end() ? "" : " "));
                    }
                    return _SendEvent_in_TEXT(flattened);
                }

                // RFC + CEF 모드
                bool SendEvent_with_flatten_json_in_CEF(
                    const std::string& signature_id,
                    const std::string& name,
                    int severity,
                    const std::map<std::string, std::string>& exts
                )  
                {   
                    std::string flattened;
                    for (auto it = exts.begin(); it != exts.end(); ++it)
                    {
                        flattened += fmt::format("{}={}{}", it->first, SyslogUtil::EscapeExtension(it->second), 
                                     (std::next(it) == exts.end() ? "" : " "));
                    }
                    return _SendEvent_in_CEF(signature_id, name, severity, flattened);
                }

                bool SendEvent_with_TEXT_in_CEF(
                    const std::string& signature_id,
                    const std::string& name,
                    int severity,
                    const std::string& text
                )  
                {   
                    // TEXT 메시지라도 CEF Extension 내부에 들어갈 때는 이스케이프가 필요함
                    return _SendEvent_in_CEF(signature_id, name, severity, SyslogUtil::EscapeExtension(text));
                }

                bool Add_tcp_server(const std::string& connector_id, const std::string& server_ip, const unsigned int& server_port) { 
                    std::lock_guard<std::mutex> lock(*mtx);
                    connections[connector_id] = std::make_shared<Connection::TCP_Connector>(server_ip, server_port);
                    return true;
                }

                bool Add_ucp_server(const std::string& connector_id, const std::string& server_ip, const unsigned int& server_port) { 
                    std::lock_guard<std::mutex> lock(*mtx);
                    connections[connector_id] = std::make_shared<Connection::UDP_Connector>(server_ip, server_port);
                    return true;
                }

                bool Remove_server(const std::string& connector_id) {
                    std::lock_guard<std::mutex> lock(*mtx);
                    if (connections.find(connector_id) != connections.end()) {
                        connections.erase(connector_id);
                        return true;
                    }
                    return false;
                }

            private:
                bool _SendEvent_in_TEXT(const std::string& TEXT)
                {
                    Rfc5424Message msg;
                    msg.header.hostname = host;
                    msg.header.app_name = app;
                    msg.header.timestamp = NowUtc();
                    return _send_to_server(msg.ToString_in_TEXT(TEXT));
                }

                bool _SendEvent_in_CEF(const std::string& sid, const std::string& name, int sev, const std::string& ext)
                {
                    Rfc5424Message msg;
                    msg.header.hostname = host;
                    msg.header.app_name = app;
                    msg.header.timestamp = NowUtc();

                    msg.msg.device_vendor  = cef_vendor;
                    msg.msg.device_product = cef_product;
                    msg.msg.device_version = cef_version;
                    msg.msg.signature_id   = sid;
                    msg.msg.name           = name;
                    msg.msg.severity       = sev;
                    msg.msg.message        = ext;

                    return _send_to_server(msg.ToString_in_CEF());
                }

                bool _send_to_server(const std::string& msg)
                {
                    std::lock_guard<std::mutex> lock(*mtx);
                    std::vector<std::thread> Threads;

                    for (auto const& [k, conn] : connections)
                    {
                        Threads.push_back(std::thread([conn, msg]() {
                            try {
                                if (conn) conn->Send(msg);
                            }
                            catch (const std::exception& e) {
                                std::cerr << "Syslog Send Error: " << e.what() << std::endl;
                            }
                        }));
                    }

                    for (auto& t : Threads) {
                        if (t.joinable()) t.join();
                    }
                    return true;
                }

                std::string NowUtc()
                {
                    std::time_t t = std::time(nullptr);
                    std::tm tm_utc{};
                    gmtime_r(&t, &tm_utc);
                    // RFC 5424용 타임스탬프 (ISO 8601)
                    return fmt::format("{:%Y-%m-%dT%H:%M:%SZ}", tm_utc);
                }
            };
        }
    }
}

#endif