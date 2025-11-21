#include <algorithm>
#include <unordered_set>
#include <libproc.h>

#include "../common/Logger.h"
#include "CProcessTree.h"
#include "../common/SystemTool.h"

// 默认构造
EAGLE_THREAT_PROCESS_INFO::EAGLE_THREAT_PROCESS_INFO()
    : UtcTime(0)
    , ProcessId(0)
    , CreateTime(0)
    , FileSize(0)
    , SignStatus(0)
    , ParentId(0)
    , ExitTime(0)
{
}

// 拷贝构造
EAGLE_THREAT_PROCESS_INFO::EAGLE_THREAT_PROCESS_INFO(const EAGLE_THREAT_PROCESS_INFO &other)
    : UtcTime(other.UtcTime)
    , ProcessId(other.ProcessId)
    , ImagePath(other.ImagePath)
    , Hash(other.Hash)
    , User(other.User)
    , SID(other.SID)
    , CommandLine(other.CommandLine)
    , CurrentDirectory(other.CurrentDirectory)
    , ProcessGuid(other.ProcessGuid)
    , ParentProcessGuid(other.ParentProcessGuid)
    , ProcFileId(other.ProcFileId)
    , SignerName(other.SignerName)
    , CreateTime(other.CreateTime)
    , FileSize(other.FileSize)
    , SignStatus(other.SignStatus)
    , fileguid(other.fileguid)
    , ParentId(other.ParentId)
    , ExitTime(other.ExitTime)
{
}

// 赋值重载
EAGLE_THREAT_PROCESS_INFO& EAGLE_THREAT_PROCESS_INFO::operator=(const EAGLE_THREAT_PROCESS_INFO &other)
{
    if (this != &other)
    {
        UtcTime = other.UtcTime;
        ProcessId = other.ProcessId;
        ImagePath = other.ImagePath;
        Hash = other.Hash;
        User = other.User;
        SID = other.SID;
        CommandLine = other.CommandLine;
        CurrentDirectory = other.CurrentDirectory;
        ProcessGuid = other.ProcessGuid;
        ParentProcessGuid = other.ParentProcessGuid;
        ProcFileId = other.ProcFileId;
        SignerName = other.SignerName;
        CreateTime = other.CreateTime;
        FileSize = other.FileSize;
        SignStatus = other.SignStatus;
        fileguid = other.fileguid;
        ParentId = other.ParentId;
        ExitTime = other.ExitTime;
    }
    return *this;
}

void EAGLE_THREAT_PROCESS_INFO::PrintProcess() const
{
    LOG_INFO("  ========= Process Info =========");
    LOG_INFO("  UtcTime:           {}", UtcTime);
    LOG_INFO("  ProcessId:         {}", ProcessId);
    LOG_INFO("  ParentId:          {}", ParentId);
    LOG_INFO("  ImagePath:         {}", ImagePath);
    LOG_INFO("  FileSize:          {}", FileSize);
    LOG_INFO("  Hash:              {}", Hash);
    LOG_INFO("  User:              {}", User);
    LOG_INFO("  SID:               {}", SID);
    LOG_INFO("  CommandLine:       {}", CommandLine);
    LOG_INFO("  CurrentDirectory:  {}", CurrentDirectory);
    LOG_INFO("  ProcessGuid:       {}", ProcessGuid);
    LOG_INFO("  ParentProcessGuid: {}", ParentProcessGuid);
    LOG_INFO("  CreateTime:        {}", CreateTime);
    LOG_INFO("  SignerName:        {}", SignerName);
    LOG_INFO("  SignStatus:        {}", SignStatus);
    LOG_INFO("  ExitTime:          {}", ExitTime);
    LOG_INFO(" \n");
}

CProcessTree* CProcessTree::shared()
{
    static CProcessTree instance;
    return &instance;
}

void CProcessTree::PrintTree(pid_t iPid, int depth)
{
    try
    {
        std::unordered_set<std::string> guidSet;
        {
            std::lock_guard<std::mutex> lock(m_mutexTree);
            for ( const auto &kv: m_procTreeMap )
            {
                if ( kv.first.PID == iPid && kv.second )
                {
                    guidSet.insert(kv.second->ProcessGuid);
                }
            }
        }

        if ( guidSet.empty() )
        {
            if ( depth == 0 )
            {
                LOG_WARN("Process {} not found in tree", iPid);
            }
            return;
        }

        bool first = true;
        for ( const auto &guid: guidSet )
        {
            // 找到该 PID + GUID 的进程信息，并快照必要字段，避免长时间持锁
            EAGLE_THREAT_PROCESS_INFO procSnap;
            bool                      found = false;
            std::vector<pid_t>        children;
            {
                std::lock_guard<std::mutex> lock(m_mutexTree);
                for ( const auto &kv: m_procTreeMap )
                {
                    if ( kv.first.PID == iPid && kv.second && kv.second->ProcessGuid == guid )
                    {
                        procSnap = *kv.second;  // 拷贝快照
                        found    = true;
                        break;
                    }
                }
                if ( found )
                {
                    for ( const auto &kv: m_procTreeMap )
                    {
                        if ( kv.first.PPID == procSnap.ProcessId )
                        {
                            children.push_back(kv.first.PID);
                        }
                    }
                }
            }

            if ( !found )
            {
                continue;
            }

            // 缩进显示层级
            // std::cout << std::string(depth * 4, ' '); // 暂时注释，格式化输出用LOG_DEBUG

            // PID 复用标记
            if ( guidSet.size() > 1 )
            {
                LOG_DEBUG("{}|- PID: {} [{}]", std::string(depth * 4, ' '), procSnap.ProcessId, (first ? "老" : "新"));
                first = false;
            }
            else
            {
                LOG_DEBUG("{}|- PID: {}", std::string(depth * 4, ' '), procSnap.ProcessId);
            }

            // 去重并递归打印子进程
            std::sort(children.begin(), children.end());
            children.erase(std::unique(children.begin(), children.end()), children.end());
            for ( size_t idx = 0; idx < children.size(); ++idx )
            {
                pid_t childPid = children[idx];
                PrintTree(childPid, depth + 1);
            }
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception during tree print: {}, target_pid={}", e.what(), iPid);
    }
}

bool CProcessTree::insertNode(EAGLE_THREAT_PROCESS_INFO *procInfo)
{
    // LOG_INFO("INSERT_PROCESS size = {}", m_procTreeMap.size());  // 注释掉高频日志
    if(!procInfo)
    {
        LOG_ERROR("insertNode: procInfo is null");
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutexTree);

    // 创建完整 Key
    ProcTreeKey fullKey;
    fullKey.PID = procInfo->ProcessId;
    fullKey.PPID = procInfo->ParentId;
    fullKey.CreateTime = procInfo->CreateTime;

    // 检查是否已存在
    auto it = m_procTreeMap.find(fullKey);
    if (it != m_procTreeMap.end())
    {
        *(it->second) = *procInfo;  // 更新
        return true;
    }

    // 插入新节点（需要分配内存）
    EAGLE_THREAT_PROCESS_INFO* newProc = new EAGLE_THREAT_PROCESS_INFO(*procInfo);
    m_procTreeMap[fullKey] = newProc;
//    newProc->PrintProcess();

    // 在PID索引中添加映射（支持PID复用，多个key可对应同一个PID）
    m_pidIndex.insert({procInfo->ProcessId, fullKey});
    return true;
}

EAGLE_THREAT_PROCESS_INFO *CProcessTree::FindByPid(pid_t pid)
{
    std::lock_guard<std::mutex> lock(m_mutexTree);
    ProcTreeKey                 pidKey;
    pidKey.PID  = pid;
    pidKey.KeyType = ProcTreeKey::PIDOnly;
    auto it     = m_procTreeMap.find(pidKey);
    if ( it != m_procTreeMap.end() )
    {
        return it->second;
    }
    return nullptr;
}

std::vector<EAGLE_THREAT_PROCESS_INFO *> CProcessTree::GetProcessChain(pid_t pid)
{
    std::vector<EAGLE_THREAT_PROCESS_INFO *> chain;
    std::lock_guard<std::mutex>              lock(m_mutexTree);

    pid_t currentPid = pid;
    int   guard      = 64;  // 防环

    while ( currentPid > 0 && guard-- > 0 )
    {
        EAGLE_THREAT_PROCESS_INFO *proc = nullptr;

        // 按 PID 查找任意进程
        for ( auto &kv: m_procTreeMap )
        {
            if ( kv.first.PID == currentPid && kv.second )
            {
                proc = kv.second;
                break;
            }
        }

        if ( proc )
        {
            chain.push_back(proc);
            // 获取父进程ID，并立即检查有效性
            // pid_t parentPid = SystemUtils::GetPPid(currentPid);
            pid_t parentPid = proc->ParentId;
            if ( parentPid <= 0 )
            {
                break;  // 到达进程树顶端，停止追踪
            }
            currentPid = parentPid;
        }
        else
        {
            break;  // 未找到进程信息，停止追踪
        }
    }

    return chain;
}

bool CProcessTree::markExit(const ProcTreeKey &key)
{
    std::lock_guard<std::mutex> lock(m_mutexTree);

    // 检查进程是否存在
    auto it = m_procTreeMap.find(key);
    if (it == m_procTreeMap.end())
    {
        LOG_WARN("markExit: Process not found, PID={}, CreateTime={}", key.PID, key.CreateTime);
        return false;
    }

    // 更新退出时间
    it->second->ExitTime = static_cast<int32_t>(time(nullptr));
    // it->second->PrintProcess();  // 注释掉，避免高频日志

    // 添加到老化列表
    AgingEntry entry;
    entry.key = key;
    entry.exitTime = std::chrono::steady_clock::now();
    m_agingList.push_back(entry);

    LOG_DEBUG("markExit: Process marked for aging, PID={}, CreateTime={}", key.PID, key.CreateTime);
    return true;
}

void CProcessTree::StartAging()
{
    if (m_agingThread.joinable())
    {
        LOG_WARN("Aging thread already running");
        return;
    }

    m_agingThreadRunning = true;
    m_agingThread = std::thread([this]()
    {
        while (m_agingThreadRunning)
        {
            try
            {
                // 每隔10秒检查一次老化队列
                std::this_thread::sleep_for(std::chrono::seconds(10));

                auto now = std::chrono::steady_clock::now();
                std::lock_guard<std::mutex> lock(m_mutexTree);

                // 清理已经退出超过30秒的进程（前提是没有子进程）
                auto it = m_agingList.begin();
                while (it != m_agingList.end())
                {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->exitTime);
                    if (elapsed.count() >= 30)  // 退出超过30秒
                    {
                        // 检查是否有子进程引用此进程
                        bool hasChildren = false;
                        for (const auto& kv : m_procTreeMap)
                        {
                            // 如果有进程的 PPID 等于当前进程的 PID，说明有子进程
                            if (kv.first.PPID == it->key.PID && kv.second && kv.second->ExitTime == 0)
                            {
                                hasChildren = true;
                                break;
                            }
                        }

                        // 只有在没有子进程的情况下才删除
                        if (!hasChildren)
                        {
                            // 查找并删除进程
                            auto procIt = m_procTreeMap.find(it->key);
                            if (procIt != m_procTreeMap.end())
                            {
                                LOG_DEBUG("Aging: Removing process PID={}, CreateTime={} (no children, 30s elapsed)",
                                         it->key.PID, it->key.CreateTime);

                                delete procIt->second;
                                m_procTreeMap.erase(procIt);

                                // 从PID索引中删除
                                auto range = m_pidIndex.equal_range(it->key.PID);
                                for (auto idx = range.first; idx != range.second; )
                                {
                                    if (idx->second == it->key)
                                    {
                                        idx = m_pidIndex.erase(idx);
                                        break;
                                    }
                                    else
                                    {
                                        ++idx;
                                    }
                                }
                            }

                            it = m_agingList.erase(it);
                        }
                        else
                        {
                            LOG_DEBUG("Aging: Keeping process PID={} (has active children)", it->key.PID);
                            ++it;
                        }
                    }
                    else
                    {
                        ++it;
                    }
                }
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Exception in aging thread: {}", e.what());
            }
        }

        LOG_INFO("Aging thread stopped");
    });
}

CProcessTree::CProcessTree()
{
    // 1、获取所有进程PID
    std::lock_guard<std::mutex> lock(m_mutexTree);
    std::vector<pid_t> vecPid;
    vecPid.clear();

    size_t estimatedCount = 4096;
    int numBytes = 0;
    while ( true )
    {
        vecPid.resize(estimatedCount);

        numBytes = proc_listpids(PROC_ALL_PIDS, 0, vecPid.data(), (int)(vecPid.size() * sizeof(pid_t)));
        if ( numBytes <= 0 )
        {
            return;  // 查询失败
        }

        int pidCount = numBytes / sizeof(pid_t);
        if ( pidCount < static_cast<int>(estimatedCount) )
        {
            vecPid.resize(pidCount);
            break;
        }

        // PID数量超过预估，扩大缓冲区
        estimatedCount *= 2;
    }
    /**
     int32_t     SignStatus;         // 21
     std::string fileguid;           // 22
     */
    // 2、获取PID列表填充信息EAGLE_THREAT_PROCESS_INFO各个字段信息。
    int successCount = 0;
    for ( const auto &pid: vecPid )
    {
        if (pid <= 0)
        {
            continue;
        }

        EAGLE_THREAT_PROCESS_INFO * pProcInfo = new EAGLE_THREAT_PROCESS_INFO();

        try
        {
            pProcInfo->UtcTime = (uint32_t)GetCreateTime(pid);
            pProcInfo->ProcessId = pid;
            pProcInfo->ImagePath = GetProcessPath(pid);
            NSString *Hash = GetSHA256(pid);
            pProcInfo->Hash = Hash ? [Hash UTF8String] : "";
            NSString *User = GetUser(pid);
            pProcInfo->User = User ? [User UTF8String] : "";
            pProcInfo->SID = std::to_string(GetUid(pid));
            NSString *CommandLine = GetCMD(pid);
            pProcInfo->CommandLine = CommandLine ? [CommandLine UTF8String] : "";
            NSString *CurrentDirectory = GetPWD(pid);
            pProcInfo->CurrentDirectory = CurrentDirectory ? [CurrentDirectory UTF8String] : "";
            pProcInfo->ProcessGuid =  GetGUID(pid);
            pProcInfo->ParentId = GetPPid(pid);
            pProcInfo->ParentProcessGuid =  GetGUID(pProcInfo->ParentId);
            pProcInfo->SignerName = GetSignerName(pProcInfo->ImagePath);
            pProcInfo->CreateTime = (int32_t)GetCreateTime(pid);
            pProcInfo->FileSize = (int32_t)GetFileSize(pid);

            // 创建完整 Key 并插入到进程树
            ProcTreeKey fullKey;
            fullKey.PID = pProcInfo->ProcessId;
            fullKey.PPID = pProcInfo->ParentId;
            fullKey.CreateTime = pProcInfo->CreateTime;
            fullKey.KeyType = ProcTreeKey::FullKey;

            // 直接插入到 map 中（构造函数中已经持有锁）
            m_procTreeMap[fullKey] = pProcInfo;
            m_pidIndex.insert({pProcInfo->ProcessId, fullKey});
            successCount++;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Exception while processing pid {}: {}", pid, e.what());
            delete pProcInfo;
            pProcInfo = nullptr;
        }
        catch (...)
        {
            LOG_ERROR("Unknown exception while processing pid {}", pid);
            delete pProcInfo;
            pProcInfo = nullptr;
        }
    }

    LOG_INFO("Process tree initialization complete: {} processes inserted out of {} total", successCount, vecPid.size());
    
    // 3、增加进程程序文件的sha256及命令行CMD缓冲区。
    
    // 4、把全部的进程信息序列化为PROTOBUF后上报。
}

CProcessTree::~CProcessTree()
{
    // 停止老化线程
    m_agingThreadRunning = false;
    if (m_agingThread.joinable())
    {
        m_agingThread.join();
    }

    // 释放进程树中所有动态分配的内存
    std::lock_guard<std::mutex> lock(m_mutexTree);
    for (auto& pair : m_procTreeMap)
    {
        delete pair.second;
    }
    m_procTreeMap.clear();
    m_pidIndex.clear();
    m_agingList.clear();
}

void CProcessTree::deleteNode(EAGLE_THREAT_PROCESS_INFO *procInfo)
{
    if (!procInfo)
    {
        LOG_ERROR("deleteNode: procInfo is null");
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutexTree);

    // 创建完整key
    ProcTreeKey fullKey;
    fullKey.PID = procInfo->ProcessId;
    fullKey.PPID = procInfo->ParentId;
    fullKey.CreateTime = procInfo->CreateTime;
    fullKey.KeyType = ProcTreeKey::FullKey;  // 设置为完整Key类型

    // 查找节点是否存在
    auto it = m_procTreeMap.find(fullKey);
    if (it == m_procTreeMap.end())
    {
        LOG_WARN("deleteNode: Process not found, PID={}, CreateTime={}", procInfo->ProcessId, procInfo->CreateTime);
        return;
    }

    // 删除进程信息结构体
    EAGLE_THREAT_PROCESS_INFO* pProc = it->second;
    pProc->PrintProcess();
    delete pProc;

    // 从主映射中删除
    m_procTreeMap.erase(it);

    // 从PID索引中删除对应的条目
    auto range = m_pidIndex.equal_range(procInfo->ProcessId);
    for (auto idx = range.first; idx != range.second; )
    {
        if (idx->second == fullKey)
        {
            idx = m_pidIndex.erase(idx);
            break;
        }
        else
        {
            ++idx;
        }
    }

    LOG_DEBUG("deleteNode: Process deleted, PID={}, CreateTime={}", procInfo->ProcessId, procInfo->CreateTime);
}
