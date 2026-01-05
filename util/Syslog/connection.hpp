#ifndef SYSLOGMANAGER_CONNECTION_HPP
#define SYSLOGMANAGER_CONNECTION_HPP

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>



namespace NDR
{
    namespace Util  
    {
        namespace Syslog
        {
            namespace Connection
            {

                // 부모클래스
                class Connector
                {
                public:
                    virtual ~Connector() = default;

                    virtual bool Connect() = 0;
                    virtual void Disconnect() = 0;
                    virtual bool Send(const std::string& msg) = 0;
                };

                class TCP_Connector : public Connector
                {
                public:
                    TCP_Connector(const std::string& ip, int port)
                        : server_ip(ip), server_port(port) {}

                    ~TCP_Connector()
                    {
                        Disconnect();
                    }

                    bool Connect() override
                    {
                        sock = socket(AF_INET, SOCK_STREAM, 0);
                        if (sock < 0)
                            return false;

                        sockaddr_in addr{};
                        addr.sin_family = AF_INET;
                        addr.sin_port = htons(server_port);

                        if (inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) <= 0)
                            return false;

                        return connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0;
                    }

                    void Disconnect() override
                    {
                        if (sock >= 0)
                        {
                            close(sock);
                            sock = -1;
                        }
                    }

                    bool Send(const std::string& msg) override
                    {
                        // 최대 2회 시도 (1차 전송 실패 시 재연결 후 2차 전송)
                        for (int i = 0; i < 2; ++i) {
                            if (sock < 0) {
                                if (!Connect()) continue; 
                            }

                            std::string framed = std::to_string(msg.size()) + " " + msg;
                            size_t totalSent = 0;
                            bool error = false;

                            while (totalSent < framed.size()) {
                                ssize_t sent = ::send(sock, framed.data() + totalSent, framed.size() - totalSent, MSG_NOSIGNAL); // broken pipe 무시
                                if (sent <= 0) {
                                    Disconnect(); // 소켓 닫기
                                    error = true;
                                    break;
                                }
                                totalSent += sent;
                            }

                            if (!error) return true; // 전송 성공
                        }
                        return false; // 2회 모두 실패
                    }

                private:
                    int sock = -1;
                    std::string server_ip;
                    int server_port;
                };

                class UDP_Connector : public Connector
                {
                public:
                    UDP_Connector(const std::string& ip, int port)
                        : server_ip(ip), server_port(port) {}

                    ~UDP_Connector()
                    {
                        Disconnect();
                    }

                    bool Connect() override
                    {
                        sock = socket(AF_INET, SOCK_DGRAM, 0);
                        if (sock < 0)
                            return false;

                        serverAddr.sin_family = AF_INET;
                        serverAddr.sin_port = htons(server_port);

                        return inet_pton(
                            AF_INET,
                            server_ip.c_str(),
                            &serverAddr.sin_addr
                        ) > 0;
                    }

                    void Disconnect() override
                    {
                        if (sock >= 0)
                        {
                            close(sock);
                            sock = -1;
                        }
                    }

                    bool Send(const std::string& msg) override
                    {
                        if (sock < 0)
                            if ( !Connect() )
                                throw std::runtime_error("CANT CONNECT TO SYSLOG UDP SERVER");

                        ssize_t sent = sendto(
                            sock,
                            msg.data(),
                            msg.size(),
                            0,
                            (sockaddr*)&serverAddr,
                            sizeof(serverAddr)
                        );

                        return sent == static_cast<ssize_t>(msg.size());
                    }

                private:
                    int sock = -1;
                    std::string server_ip;
                    int server_port;
                    sockaddr_in serverAddr{};
                };

            }
        }
    }
}

#endif