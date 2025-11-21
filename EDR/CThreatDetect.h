#ifndef CTHREATDETECT_H
#define CTHREATDETECT_H

#include <cstdint>
#include <memory>

#pragma mark -FuncSwitch
#define EDR_FEATURE_PROCESS_TREE                0x00000001  // 进程树
#define EDR_FEATURE_PROCESS_START               0x00000002  // 进程启动检测
#define EDR_FEATURE_FILE_CREATE                 0x00000004  // 文件创建检测
#define EDR_FEATURE_FILE_RENAME                 0x00000008  // 文件重命名检测
#define EDR_FEATURE_NETWORK_MONITOR             0x00000010  // 网络监测
#define EDR_FEATURE_OFF                         (EDR_FEATURE_PROCESS_TREE)
#define EDR_FEATURE_ALL                          (EDR_FEATURE_PROCESS_START|EDR_FEATURE_PROCESS_TREE|EDR_FEATURE_FILE_CREATE|EDR_FEATURE_FILE_RENAME|EDR_FEATURE_NETWORK_MONITOR)

class CThreatDetect
{
public:
    static CThreatDetect *Shared();
    bool SetSwitch(uint32_t iSwitch);
    uint32_t GetSwitch();

private:
    CThreatDetect();
    ~CThreatDetect();
    CThreatDetect(const CThreatDetect&) = delete;
    CThreatDetect& operator=(const CThreatDetect&) = delete;

    class Impl;
    std::unique_ptr<Impl> m_pImpl;
};
#endif // !CTHREATDETECT_H
