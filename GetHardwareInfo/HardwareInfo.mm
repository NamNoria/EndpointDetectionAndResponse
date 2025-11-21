#include "HardwareInfo.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <IOKit/IOKitLib.h>
// #include <IOKit/IOPlatformExpert.h> // 需要在macOS SDK，并配置头文件路径时使用，否则注释掉
#include <sstream>
#include <cstdio>
#include <memory>
#include <array>

// 获取 Mac 基本信息
std::string HardwareInfo::GetBasicInfo()
{
    stBasicInfo info;

    // 获取型号名称
    size_t len;
    char model[256] = {0};
    len = sizeof(model);
    if (sysctlbyname("hw.model", &model, &len, NULL, 0) == 0)
    {
        info.modelName = model;
    }
    // 型号 (以硬件model为例，通常这两个信息相同)
    info.modelNumber = info.modelName;

    // CPU核数
    int32_t coreCount = 0;
    len = sizeof(coreCount);
    if (sysctlbyname("hw.physicalcpu", &coreCount, &len, NULL, 0) == 0)
    {
        info.coreCount = std::to_string(coreCount);
    }

    // 预置UDID：优先尝试 IOKit 的相关属性，其次回退 system_profiler 解析
    info.udid = "";

    // 型号标识符
    char identifier[256] = {0};
    len = sizeof(identifier);
    if (sysctlbyname("hw.model", &identifier, &len, NULL, 0) == 0)
    {
        info.modelIdentifier = identifier;
    }

    // 芯片信息
    {
        // Intel: machdep.cpu.brand_string 可用
        char brand[256] = {0};
        size_t brandLen = sizeof(brand);
        bool chipSet = false;
        if (sysctlbyname("machdep.cpu.brand_string", &brand, &brandLen, NULL, 0) == 0 && brand[0] != '\0')
        {
            info.chip = brand;
            chipSet = true;
        }
        if (!chipSet)
        {
            // 判断是否为 Apple Silicon
            int arm64 = 0; size_t arm64Len = sizeof(arm64);
            if (sysctlbyname("hw.optional.arm64", &arm64, &arm64Len, NULL, 0) == 0 && arm64 == 1)
            {
                // 基于型号标识符做常见映射（保守：未知时写 Apple Silicon）
                if (!info.modelIdentifier.empty())
                {
                    if (info.modelIdentifier.rfind("MacBookPro17,", 0) == 0 ||
                        info.modelIdentifier.rfind("MacBookAir10,", 0) == 0 ||
                        info.modelIdentifier.rfind("Macmini9,", 0) == 0 ||
                        info.modelIdentifier.rfind("iMac21,", 0) == 0)
                    {
                        info.chip = "Apple M1";
                    }
                    else if (info.modelIdentifier.rfind("MacBookPro18,", 0) == 0)
                    {
                        info.chip = "Apple M1 Pro/Max";
                    } else if (info.modelIdentifier.rfind("MacBookPro20,", 0) == 0 || info.modelIdentifier.rfind("MacBookAir15,", 0) == 0)
                    {
                        info.chip = "Apple M2 系列";
                    } else
                    {
                        info.chip = "Apple Silicon";
                    }
                }
                else
                {
                    info.chip = "Apple Silicon";
                }
                chipSet = true;
            }
        }
        if (!chipSet && info.chip.empty())
        {
            info.chip = ""; // 实在无法确定则留空
        }
    }

    // 硬件UUID（IOPlatformUUID）
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (platformExpert)
    {
        // 尝试读取 ProvisioningUDID（部分机型存在）
        if (info.udid.empty())
        {
            CFTypeRef prov = IORegistryEntryCreateCFProperty(platformExpert, CFSTR("ProvisioningUDID"), kCFAllocatorDefault, 0);
            if (prov)
            {
                if (CFGetTypeID(prov) == CFStringGetTypeID())
                {
                    char buf[256] = {0};
                    CFStringGetCString((CFStringRef)prov, buf, sizeof(buf), kCFStringEncodingUTF8);
                    info.udid = buf;
                }
                CFRelease(prov);
            }
        }
        if (info.udid.empty())
        {
            CFTypeRef prov2 = IORegistryEntryCreateCFProperty(platformExpert, CFSTR("HardwareUDID"), kCFAllocatorDefault, 0);
            if (prov2)
            {
                if (CFGetTypeID(prov2) == CFStringGetTypeID())
                {
                    char buf[256] = {0};
                    CFStringGetCString((CFStringRef)prov2, buf, sizeof(buf), kCFStringEncodingUTF8);
                    info.udid = buf;
                }
                CFRelease(prov2);
            }
        }

        CFTypeRef uuid = IORegistryEntryCreateCFProperty(platformExpert, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        if (uuid)
        {
            if (CFGetTypeID(uuid) == CFStringGetTypeID())
            {
                char uuidStr[128] = {0};
                CFStringGetCString((CFStringRef)uuid, uuidStr, sizeof(uuidStr), kCFStringEncodingUTF8);
                info.hardwareUUID = uuidStr;
            }
            CFRelease(uuid);
        }
        IOObjectRelease(platformExpert);
    }

    // 若 IOKit 未获得 UDID，尝试 system_profiler（非API，尽量作为兜底）
    if (info.udid.empty())
    {
        auto runCommand = [](const char* cmd) -> std::string
        {
            std::array<char, 512> buffer{};
            std::string result;
            std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
            if (!pipe)
            {
                return result;
            }
            while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
            {
                result.append(buffer.data());
            }
            return result;
        };
        // 强制英文环境，便于解析关键字；若失败也能匹配中文“设备标识符/UDID”
        std::string sp = runCommand("/usr/sbin/system_profiler SPHardwareDataType 2>/dev/null");
        if (!sp.empty())
        {
            auto findValue = [&](const char* key) -> std::string
            {
                size_t pos = sp.find(key);
                if (pos == std::string::npos)
                {
                    return "";
                }
                size_t colon = sp.find(':', pos);
                if (colon == std::string::npos)
                {
                    return "";
                }
                size_t start = colon + 1;
                while (start < sp.size() && (sp[start] == ' ' || sp[start] == '\t'))
                {
                    start++;
                }
                size_t end = sp.find('\n', start);
                if (end == std::string::npos)
                {
                    end = sp.size();
                }
                std::string val = sp.substr(start, end - start);
                // 去掉收尾空白
                while (!val.empty() && (val.back() == '\r' || val.back() == ' ' || val.back() == '\t'))
                {
                    val.pop_back();
                }
                return val;
            };
            std::string v = findValue("Provisioning UDID");
            
            if (v.empty())
            {
                v = findValue("设备标识符");
            }
            
            if (v.empty())
            {
                v = findValue("UDID");
            }
            
            if (!v.empty())
            {
                info.udid = v;
            }
        }
    }

    std::stringstream ss;
    ss << "modelName: " << info.modelName << "\n";
    ss << "modelNumber: " << info.modelNumber << "\n";
    ss << "coreCount: " << info.coreCount << "\n";
    ss << "udid: " << info.udid << "\n";
    ss << "modelIdentifier: " << info.modelIdentifier << "\n";
    ss << "chip: " << info.chip << "\n";
    ss << "hardwareUUID: " << info.hardwareUUID << "\n";
    return ss.str();
}

// 获取音频信息
std::string HardwareInfo::GetAudioInfo()
{
    // 使用 system_profiler 按设备段落解析出默认输入/输出设备名称
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 1024> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
        {
            return result;
        }
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };

    std::string sp = runCommand("/usr/sbin/system_profiler SPAudioDataType 2>/dev/null");
    if (sp.empty())
    {
        return "";
    }

    std::string line;
    std::stringstream in(sp);
    std::string currentDeviceName;
    bool currentIsDefaultInput = false;
    bool currentIsDefaultOutput = false;
    std::string currentManufacturer;
    std::string currentSampleRate;
    std::string defaultInputName;
    std::string defaultOutputName;
    std::string defaultManufacturer;
    std::string defaultSampleRate;

    auto trim = [](std::string s)
    {
        while (!s.empty() && (s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
        {
            s.pop_back();
        }
        
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
        {
            return s.substr(i);
        }
    };

    while (std::getline(in, line))
    {
        bool isHeader = false;
        if (!line.empty() && line.find_first_not_of(" \t") == 0)
        {
            if (!line.empty() && line.back() == ':')
            {
                isHeader = true;
            }
            else if (line.size() >= 3 && line.compare(line.size() - 3, 3, "：") == 0)
            {
                isHeader = true;
            }
        }
        if (isHeader)
        {
            if (currentIsDefaultInput && defaultInputName.empty())
            {
                defaultInputName = currentDeviceName;
            }
            
            if (currentIsDefaultOutput && defaultOutputName.empty())
            {
                defaultOutputName = currentDeviceName;
                if (defaultManufacturer.empty())
                {
                    defaultManufacturer = currentManufacturer;
                }
                if (defaultSampleRate.empty())
                {
                    defaultSampleRate = currentSampleRate;
                }
            }
            
            if (!line.empty() && line.back() == ':')
            {
                currentDeviceName = trim(line.substr(0, line.size() - 1));
            } else if (line.size() >= 3 && line.compare(line.size() - 3, 3, "：") == 0)
            {
                currentDeviceName = trim(line.substr(0, line.size() - 3));
            } else
            {
                currentDeviceName = trim(line);
            }
            currentIsDefaultInput = false;
            currentIsDefaultOutput = false;
            currentManufacturer.clear();
            currentSampleRate.clear();
            continue;
        }

        std::string t = trim(line);
        if (t.rfind("默认输入设备：", 0) == 0 || t.rfind("Default Input Device:", 0) == 0)
        {
            std::string val = trim(t.substr(t.find_first_of(":：") + 1));
            if (val == "是" || val == "Yes")
            {
                currentIsDefaultInput = true;
            }
        }
        else if (t.rfind("默认输出设备：", 0) == 0 || t.rfind("Default Output Device:", 0) == 0)
        {
            std::string val = trim(t.substr(t.find_first_of(":：") + 1));
            if (val == "是" || val == "Yes")
            {
                currentIsDefaultOutput = true;
            }
        }
        else if (t.rfind("生产企业：", 0) == 0 || t.rfind("Manufacturer:", 0) == 0)
        {
            currentManufacturer = trim(t.substr(t.find_first_of(":：") + 1));
        }
        else if (t.rfind("当前采样速率：", 0) == 0 || t.rfind("Current Sample Rate:", 0) == 0 || t.rfind("Current SampleRate:", 0) == 0)
        {
            currentSampleRate = trim(t.substr(t.find_first_of(":：") + 1));
        }
    }
    
    if (currentIsDefaultInput && defaultInputName.empty())
    {
        defaultInputName = currentDeviceName;
    }
    
    if (currentIsDefaultOutput && defaultOutputName.empty())
    {
        defaultOutputName = currentDeviceName;
        if (defaultManufacturer.empty())
        {
            defaultManufacturer = currentManufacturer;
        }
        if (defaultSampleRate.empty())
        {
            defaultSampleRate = currentSampleRate;
        }
    }

    std::stringstream ss;
    ss << "audio.input.name: " << defaultInputName << "\n";
    ss << "audio.output.name: " << defaultOutputName << "\n";
    ss << "audio.manufacturer: " << defaultManufacturer << "\n";
    ss << "audio.sampleRate: " << defaultSampleRate << "\n";
    return ss.str();
}

// 获取显示器信息
std::string HardwareInfo::GetDisplayInfo()
{
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 512> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
        {
            return result;
        }
        
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };
    std::string sp = runCommand("/usr/sbin/system_profiler SPDisplaysDataType 2>/dev/null");
    if (sp.empty()) return "";
    auto findValueFrom = [&](const std::string& src, const char* key) -> std::string
    {
        size_t pos = src.find(key);
        if (pos == std::string::npos)
        {
            return "";
        }
        size_t colon = src.find(':', pos);
        if (colon == std::string::npos)
        {
            return "";
        }
        size_t start = colon + 1;
        while (start < src.size() && (src[start] == ' ' || src[start] == '\t')) start++;
        size_t end = src.find('\n', start);
        if (end == std::string::npos)
        {
            end = src.size();
        }
        std::string val = src.substr(start, end - start);
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ' || val.back() == '\t'))
        {
            val.pop_back();
        }
        return val;
    };

    // 名称：在“显示器：/Displays:”段落后的首个设备标题
    std::string name;
    {
        std::stringstream s2(sp);
        std::string ln;
        bool inDisplay = false;
        while (std::getline(s2, ln))
        {
            while (!ln.empty() && (ln.back()=='\r'||ln.back()==' '||ln.back()=='\t')) ln.pop_back();
            size_t i=0; while (i<ln.size() && (ln[i]==' '||ln[i]=='\t')) i++;
            std::string t = ln.substr(i);
            if (t == "显示器：" || t == "Displays:") { inDisplay = true; continue; }
            if (inDisplay && !t.empty() && (t.back()==':' || (t.size()>=3 && t.compare(t.size()-3,3,"：")==0)))
            {
                if (t.back()==':')
                {
                    name = t.substr(0, t.size()-1);
                }
                else
                {
                    name = t.substr(0, t.size()-3);
                }
                break;
            }
        }
    }
    std::string type = findValueFrom(sp, "显示器类型");
    
    if (type.empty())
    {
        type = findValueFrom(sp, "UI Looks like");
    }
    std::string resolution = findValueFrom(sp, "分辨率");
    
    if (resolution.empty())
    {
        resolution = findValueFrom(sp, "Resolution");
    }
    
    std::string connectionType = findValueFrom(sp, "连接类型");
    
    if (connectionType.empty())
    {
        connectionType = findValueFrom(sp, "Connection Type");
    }

    std::stringstream ss;
    ss << "display.name: " << name << "\n";
    ss << "display.type: " << type << "\n";
    ss << "display.resolution: " << resolution << "\n";
    ss << "display.connectionType: " << connectionType << "\n";
    return ss.str();
}

// 获取GPU信息
std::string HardwareInfo::GetGPUInfo()
{
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 512> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
        {
            return result;
        }
        
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };
    std::string sp = runCommand("/usr/sbin/system_profiler SPDisplaysDataType 2>/dev/null");
    if (sp.empty())
    {
        return "";
    }
    auto findValue = [&](const char* key) -> std::string
    {
        size_t pos = sp.find(key);
        if (pos == std::string::npos)
        {
            return "";
        }
        size_t colon = sp.find(':', pos);
        
        if (colon == std::string::npos)
        {
            return "";
        }
        size_t start = colon + 1;
        
        while (start < sp.size() && (sp[start] == ' ' || sp[start] == '\t'))
        {
            start++;
        }
        size_t end = sp.find('\n', start);
        
        if (end == std::string::npos)
        {
            end = sp.size();
        }
        
        std::string val = sp.substr(start, end - start);
        
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ' || val.back() == '\t'))
        {
            val.pop_back();
        }
        return val;
    };
    std::string name = findValue("芯片组型号");
    if (name.empty())
    {
        name = findValue("Chipset Model");
    }
    
    std::string chipModel = name;
    std::string totalCores = findValue("核总数");
    
    if (totalCores.empty())
    {
        totalCores = findValue("Total Number of Cores");
    }
    std::string vendor = findValue("供应商");
    
    if (vendor.empty())
    {
        vendor = findValue("Vendor");
    }

    std::stringstream ss;
    ss << "gpu.name: " << name << "\n";
    ss << "gpu.chipModel: " << chipModel << "\n";
    ss << "gpu.totalCores: " << totalCores << "\n";
    ss << "gpu.vendor: " << vendor << "\n";
    return ss.str();
}

// 获取网络信息
std::string HardwareInfo::GetNetworkInfo()
{
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 1024> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
        {
            return result;
        }
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };
    std::string sp = runCommand("LANG=C /usr/sbin/system_profiler SPNetworkDataType 2>/dev/null");
    if (sp.empty())
    {
        return "";
    }
    auto findValue = [&](const char* key) -> std::string
    {
        size_t pos = sp.find(key);
        if (pos == std::string::npos)
        {
            return "";
        }
        size_t colon = sp.find(':', pos);
        if (colon == std::string::npos)
        {
            return "";
        }
        size_t start = colon + 1;
        while (start < sp.size() && (sp[start] == ' ' || sp[start] == '\t')) start++;
        size_t end = sp.find('\n', start);
        if (end == std::string::npos)
        {
            end = sp.size();
        }
        std::string val = sp.substr(start, end - start);
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ' || val.back() == '\t'))
        {
            val.pop_back();
        }
        return val;
    };
    std::string name = findValue("Interface");
    std::string systemDevice = findValue("BSD Device Name");
    std::string mac = findValue("Ethernet Address");
    if (mac.empty())
    {
        mac = findValue("MAC Address");
    }

    std::stringstream ss;
    ss << "network.name: " << name << "\n";
    ss << "network.systemDevice: " << systemDevice << "\n";
    ss << "network.macAddress: " << mac << "\n";
    return ss.str();
}

// 获取存储设备信息
std::string HardwareInfo::GetStorageInfo()
{
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 1024> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
        {
            return result;
        }
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };
    // 以 SPNVMeDataType 优先，其次 SPStorageDataType
    std::string sp = runCommand("LANG=C /usr/sbin/system_profiler SPNVMeDataType 2>/dev/null");
    if (sp.empty())
    {
        sp = runCommand("LANG=C /usr/sbin/system_profiler SPStorageDataType 2>/dev/null");
    }
    if (sp.empty())
    {
        return "";
    }
    auto findValue = [&](const char* key) -> std::string
    {
        size_t pos = sp.find(key);
        if (pos == std::string::npos)
        {
            return "";
        }
        size_t colon = sp.find(':', pos);
        if (colon == std::string::npos)
        {
            return "";
        }
        size_t start = colon + 1;
        while (start < sp.size() && (sp[start] == ' ' || sp[start] == '\t'))
        {
            start++;
        }
        size_t end = sp.find('\n', start);
        if (end == std::string::npos)
        {
            end = sp.size();
        }
        std::string val = sp.substr(start, end - start);
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ' || val.back() == '\t'))
        {
            val.pop_back();
        }
        return val;
    };
    std::string deviceName = findValue("Device Name");
    if (deviceName.empty())
    {
        deviceName = findValue("Model");
    }
    std::string capacity = findValue("Capacity");
    std::string model = findValue("Model");
    std::string serial = findValue("Serial Number");

    std::stringstream ss;
    ss << "storage.deviceName: " << deviceName << "\n";
    ss << "storage.capacity: " << capacity << "\n";
    ss << "storage.model: " << model << "\n";
    ss << "storage.serialNumber: " << serial << "\n";
    return ss.str();
}

// 获取内存分区信息
std::string HardwareInfo::GetMemoryInfo()
{
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 1024> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
        {
            return result;
        }
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };
    // 使用 diskutil 解析分区信息
    std::string sp = runCommand("/usr/sbin/diskutil list 2>/dev/null");
    if (sp.empty())
    {
        return "";
    }

    // 简单抓取第一条 APFS/GPT 分区信息
    std::string name;
    std::string capacity;
    std::string bsdName;
    std::string contentType;

    // 找到带有 diskXsY 的行并解析
    size_t pos = sp.find("disk0s");
    if (pos == std::string::npos)
    {
        pos = sp.find("disk1s");
    }
    if (pos != std::string::npos)
    {
        // 往左找一行开头
        size_t lineStart = sp.rfind('\n', pos);
        if (lineStart == std::string::npos)
        {
            lineStart = 0;
        }
        else
        {
            lineStart += 1;
        }
        size_t lineEnd = sp.find('\n', pos);
        if (lineEnd == std::string::npos)
        {
            lineEnd = sp.size();
        }
        std::string line = sp.substr(lineStart, lineEnd - lineStart);
        // 直接记录 BSD 名称
        size_t bsdPos = line.find("disk");
        if (bsdPos != std::string::npos)
        {
            bsdName = line.substr(bsdPos);
            // 截断到空白
            size_t space = bsdName.find(' ');
            if (space != std::string::npos)
            {
                bsdName = bsdName.substr(0, space);
            }
        }
        // 名称尝试在该行前面的 token
        // 容量不易稳定解析，暂时留空或从括号中取
        size_t paren = line.find('(');
        if (paren != std::string::npos)
        {
            size_t parenEnd = line.find(')', paren);
            if (parenEnd != std::string::npos)
            {
                capacity = line.substr(paren + 1, parenEnd - paren - 1);
            }
        }
        // 内容类型
        if (line.find("APFS") != std::string::npos)
        {
            contentType = "APFS";
        }
        else if (line.find("Apple_APFS") != std::string::npos)
        {
            contentType = "Apple_APFS";
        }
    }

    std::stringstream ss;
    ss << "memory.name: " << name << "\n";
    ss << "memory.capacity: " << capacity << "\n";
    ss << "memory.bsdName: " << bsdName << "\n";
    ss << "memory.contentType: " << contentType << "\n";
    return ss.str();
}

// 获取主板信息
std::string HardwareInfo::GetMotherboardInfo()
{
    auto runCommand = [](const char* cmd) -> std::string
    {
        std::array<char, 512> buffer{};
        std::string result;
        std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), pclose);
        if (!pipe) return result;
        while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr)
        {
            result.append(buffer.data());
        }
        return result;
    };
    std::string sp = runCommand("/usr/sbin/system_profiler SPHardwareDataType 2>/dev/null");
    if (sp.empty())
    {
        return "";
    }
    auto findValue = [&](const char* key) -> std::string
    {
        size_t pos = sp.find(key);
        if (pos == std::string::npos)
        {
            return "";
        }
        size_t colon = sp.find(':', pos);
        if (colon == std::string::npos)
        {
            return "";
        }
        size_t start = colon + 1;
        while (start < sp.size() && (sp[start] == ' ' || sp[start] == '\t'))
        {
            start++;
        }
        size_t end = sp.find('\n', start);
        if (end == std::string::npos)
        {
            end = sp.size();
        }
        std::string val = sp.substr(start, end - start);
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ' || val.back() == '\t'))
        {
            val.pop_back();
        }
        return val;
    };
    std::string modelIdentifier = findValue("型号标识符");
    if (modelIdentifier.empty())
    {
        modelIdentifier = findValue("Model Identifier");
    }
    std::string firmwareVersion = findValue("固件版本");
    if (firmwareVersion.empty())
    {
        firmwareVersion = findValue("Boot ROM Version");
    }
    if (firmwareVersion.empty())
    {
        firmwareVersion = findValue("iBoot");
    }
    std::string bootUUID = findValue("启动 UUID");
    if (bootUUID.empty())
    {
        bootUUID = findValue("Boot UUID");
    }
    if (bootUUID.empty())
    {
        // 尝试从 ioreg 读取
        std::string ioreg = runCommand("/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | /usr/bin/grep \"boot-uuid\" 2>/dev/null");
        size_t quote = ioreg.find('"');
        if (quote != std::string::npos)
        {
            size_t quote2 = ioreg.find('"', quote + 1);
            if (quote2 != std::string::npos)
            {
                bootUUID = ioreg.substr(quote + 1, quote2 - quote - 1);
            }
        }
    }
    std::string serialNumberCmd = "system_profiler SPHardwareDataType | grep \"Serial Number\"";

    std::stringstream ss;
    ss << "motherboard.modelIdentifier: " << modelIdentifier << "\n";
    ss << "motherboard.firmwareVersion: " << firmwareVersion << "\n";
    ss << "motherboard.bootUUID: " << bootUUID << "\n";
    ss << "motherboard.serialNumberCmd: " << serialNumberCmd << "\n";
    return ss.str();
}

// 获取全部硬件信息
std::string HardwareInfo::GetHardwareInfo(stMacHardwareInfo* stInfo)
{
    // 先返回基础信息，其他项逐步补充
    std::stringstream ss;
    ss << GetBasicInfo();
    ss << GetAudioInfo();
    ss << GetDisplayInfo();
    ss << GetGPUInfo();
    ss << GetNetworkInfo();
    ss << GetStorageInfo();
    ss << GetMemoryInfo();
    ss << GetMotherboardInfo();

    // 如有传入结构体指针，暂不填充，后续实现各项采集后再赋值
    (void)stInfo;
    return ss.str();
}
