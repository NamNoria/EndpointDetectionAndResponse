#ifndef HARDWAREINFO_H
#define HARDWAREINFO_H

#include <string>

struct stBasicInfo
{
    std::string modelName;        // 型号名称
    std::string modelNumber;      // 型号
    std::string coreCount;        // 核总数
    std::string udid;             // 预置UDID
    std::string modelIdentifier;  // 型号标识符
    std::string chip;             // 芯片
    std::string hardwareUUID;     // 硬件UUID
};

struct stAudioInfo
{
    std::string name;             // 名称，例如：MacBook Pro麦克风
    std::string manufacturer;     // 生产企业，例如：Apple Inc
    int sampleRate;               // 当前采样速率（Hz）
};

struct stDisplayInfo
{
    std::string name;           // 名称，例如：彩色LCD
    std::string type;           // 显示器类型，例如：内建视网膜LCD
    std::string resolution;     // 分辨率，例如：2560 x 1600视网膜显示屏
    std::string connectionType; // 连接类型，例如：内置
};

struct stGPUInfo
{
    std::string name;       // 名称，例如：Apple M1
    std::string chipModel;  // 芯片组型号，例如：Apple M1
    int totalCores;         // 核总数，例如：8
    std::string vendor;     // 供应商，例如：Apple (0x106b)
};

struct stNetworkInfo
{
    std::string name;         // 网卡名称，例如：AX88179A
    std::string systemDevice; // 系统设备名称
    std::string macAddress;   // MAC 地址
};

struct stStorageInfo
{
    std::string deviceName;   // 设备名称，例如：APPLE SSD AP1024Q
    std::string capacity;     // 容量，例如：1 TB（1,000,555,581,440字节）
    std::string model;        // 型号，例如：APPLE SSD AP1024Q
    std::string serialNumber; // 序列号，例如：0ba016114328d809
};

struct stMemoryInfo
{
    std::string name;        // 卷名称，例如：iSCPreboot、Macintosh HD - Data、Recovery
    std::string capacity;    // 容量，例如：524.3 MB（524,288,000字节）
    std::string bsdName;     // BSD 名称，例如：disk0s1
    std::string contentType; // 内容类型，例如：Apple_APFS_ISC
};

struct stMotherboardInfo
{
    std::string modelIdentifier; // 型号标识符，例如：MacBookPro17,1
    std::string firmwareVersion; // 固件版本，例如：iBoot-13822.1.2
    std::string bootUUID;        // 启动 UUID，例如：C0BA7B16-A7B9-43D8-8AD1-CB1657C4468D
    std::string serialNumberCmd; // 获取序列号的命令，例如：system_profiler SPHardwareDataType | grep "Serial Number"
};

struct stMacHardwareInfo
{
    stBasicInfo basicInfo;
    stAudioInfo audio;
    stDisplayInfo display;
    stGPUInfo gpu;
    stNetworkInfo network;
    stStorageInfo storage;
    stMemoryInfo memory;
    stMotherboardInfo motherboard;
};

class HardwareInfo
{
public:
    std::string GetHardwareInfo(stMacHardwareInfo* stInfo);
private:
    std::string GetBasicInfo();
    std::string GetAudioInfo();
    std::string GetDisplayInfo();
    std::string GetGPUInfo();
    std::string GetNetworkInfo();
    std::string GetStorageInfo();
    std::string GetMemoryInfo();
    std::string GetMotherboardInfo();
public:
private:
};

#endif // !HARDWAREINFO_H
