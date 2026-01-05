#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <linux/types.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>
#include <csignal>
#include <cerrno>
#include <cstring>   // strerror
#include <net/if.h>  // if_nametoindex
#include <ifaddrs.h>
#include <vector>
#include <thread> 
#include <tuple>
#include <unordered_map>
#include <cstdlib>
#include <chrono>    // C++11 chrono 라이브러리
#include <cstdint>   // uint64_t를 위해
#include <atomic>
#include <fmt/core.h>
#include <utility> 
#include <fstream>
#include <iomanip>
#include <fmt/chrono.h>
#include <ctime> 

namespace NDR
{
    namespace Util
    {
        namespace timestamp
        {
            // Chrono -> __u64 기반 타임스탬프
            inline __u64 Get_Real_Timestamp()
            {
                auto now = std::chrono::system_clock::now();
                auto nano_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
                return static_cast<__u64>(nano_since_epoch.count());
            }

            // nano to string
            inline std::string Timestamp_From_Nano(__u64 nano_since_epoch)
            {
                 using namespace std::chrono;

                // 1. 나노초를 시스템 시간(time_point)으로 변환
                auto tp = system_clock::time_point(nanoseconds(nano_since_epoch));

                // 2. time_point를 time_t(초 단위 정수)로 변환
                auto tt = system_clock::to_time_t(tp);

                // 3. [핵심] time_t를 로컬 시간이 아닌 "UTC 구조체(tm)"로 분해
                std::tm utc_tm;
                #if defined(_WIN32) || defined(_WIN64)
                    gmtime_s(&utc_tm, &tt); // Windows
                #else
                    gmtime_r(&tt, &utc_tm); // Linux/Unix
                #endif

                // 4. 밀리초(또는 나노초) 부분 계산
                auto fractional_seconds = nano_since_epoch % 1'000'000'000; // 나노초까지 찍고 싶다면

                // 5. 포맷팅 (이제 utc_tm에는 UTC 기준 시각이 들어있습니다)
                //    Z를 붙여도 논리적으로 완벽합니다.
                //    나노초 9자리까지 찍으려면 {:09} 사용
                return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:09}Z", utc_tm, fractional_seconds);
            }

            // nano to timespec
            inline bool Get_timespec_by_Timestamp(__u64 input_timestamp, struct timespec* output)
            {
                if(!output)
                    return false;

                struct timespec ts;
                ts.tv_sec = input_timestamp / 1000000000ULL;        // 나노초를 초로 변환
                ts.tv_nsec = input_timestamp % 1000000000ULL;        // 남은 부분을 나노초로 변환

                *output = ts;

                return true;
            }
        }
    }
}

#endif