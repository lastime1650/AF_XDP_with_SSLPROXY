#ifndef FILE_HANDLER_HPP
#define FILE_HANDLER_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <regex>

namespace NDR
{
    namespace Util
    {
        namespace File
        {
            class FileHandler {
                public:
                    FileHandler() = default;

                    // 파일 존재여부 체크
                    bool is_valid_file(std::string filepath)
                    {
                        std::ifstream inFile(filepath, std::ios::binary);
                        bool is_valid = inFile.is_open();
                        inFile.close();
                        return is_valid;
                    }

                    // Regex 기반 파일 찾기
                    std::vector<std::string> findFilesByPattern(const std::string& dirPath, std::regex& pattern) {
                        std::vector<std::string> matchedFiles;

                        for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                            if (entry.is_regular_file()) {
                                const std::string filename = entry.path().filename().string();
                                if (std::regex_match(filename, pattern)) {
                                    matchedFiles.push_back(entry.path().string());
                                }
                            }
                        }

                        return matchedFiles;
                    }

                    // 바이너리 파일 쓰기
                    bool writeToFile(const std::string& filename, const std::vector<uint8_t>& data, bool append = false) {
                        std::ofstream outFile;
                        
                        if (append)
                            outFile.open(filename, std::ios::binary | std::ios::app);
                        else
                            outFile.open(filename, std::ios::binary | std::ios::trunc);

                        if (!outFile.is_open()) {
                            std::cerr << "파일 열기 실패: " << filename << std::endl;
                            return false;
                        }

                        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
                        outFile.close();
                        return true;
                    }

                    // 바이너리 파일 읽기
                    std::vector<uint8_t> readFromFile(const std::string& filename) {
                        std::ifstream inFile(filename, std::ios::binary);
                        std::vector<uint8_t> data;

                        if (!inFile.is_open()) {
                            std::cerr << "파일 열기 실패: " << filename << std::endl;
                            return data;
                        }

                        inFile.seekg(0, std::ios::end);
                        std::streamsize size = inFile.tellg();
                        inFile.seekg(0, std::ios::beg);

                        if (size > 0) {
                            data.resize(size);
                            inFile.read(reinterpret_cast<char*>(data.data()), size);
                        }

                        inFile.close();
                        return data;
                    }
                };
        }
    }
}


#endif // FILE_HANDLER_HPP
