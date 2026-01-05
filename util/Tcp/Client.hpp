#ifndef TCP_MANAGER_HPP
#define TCP_MANAGER_HPP

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
        namespace Tcp
        {
            class TcpManager
            {
            public:
                TcpManager(const std::string& ip, int port)
                    : server_ip(ip), server_port(port)
                {
                    sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) {
                        throw std::runtime_error("Socket creation failed");
                    }
                }

                ~TcpManager()
                {
                    if (sock >= 0)
                        close(sock);
                }

                bool Connect()
                {
                    sockaddr_in serverAddr {};
                    serverAddr.sin_family = AF_INET;
                    serverAddr.sin_port = htons(server_port);

                    if (inet_pton(AF_INET, server_ip.c_str(), &serverAddr.sin_addr) <= 0)
                        return false;

                    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
                        return false;

                    return true;
                }

                bool Disconnect()
                {
                    if (sock >= 0) {
                        close(sock);
                        sock = -1;
                    }
                    return true;
                }

                bool Send(const std::vector<unsigned char>& data)
                {
                    uint32_t dataSize = static_cast<uint32_t>(data.size());
                    uint32_t dataSizeNet = (dataSize);

                    // 길이(4byte) 먼저 전송
                    if (::send(sock, &dataSizeNet, sizeof(dataSizeNet), 0) < 0) {
                        std::cout << "Send length failed\n";
                        return false;
                    }

                    // 본문 전송
                    size_t totalSent = 0;
                    while (totalSent < data.size())
                    {
                        ssize_t sent = ::send(sock, data.data() + totalSent,
                            data.size() - totalSent, 0);

                        if (sent <= 0) {
                            std::cout << "Send data failed\n";
                            return false;
                        }

                        totalSent += sent;
                    }

                    return true;
                }

                bool Receive(std::vector<unsigned char>& buffer)
                {
                    uint32_t sizeNet = 0;
                    ssize_t received = recv(sock, &sizeNet, sizeof(sizeNet), 0);
                    if (received <= 0)
                        return false;

                    uint32_t expectedSize = ntohl(sizeNet);
                    buffer.resize(expectedSize);

                    size_t totalReceived = 0;
                    while (totalReceived < expectedSize)
                    {
                        ssize_t r = recv(sock,
                            buffer.data() + totalReceived,
                            expectedSize - totalReceived,
                            0);

                        if (r <= 0)
                            return false;

                        totalReceived += r;
                    }

                    return true;
                }

            private:
                int sock = -1;
                std::string server_ip;
                int server_port;
            };
        }
    }
}

#endif
