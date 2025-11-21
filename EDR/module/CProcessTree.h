#ifndef CPROCESSTREE_H
#define CPROCESSTREE_H

#include <mutex>
#include <thread>
#include <list>
#include <unordered_map>

struct ProcTreeKey
{
    enum KeyType
    {
        PIDOnly,
        FullKey
    };

    int32_t     PID        = 0;
    int32_t     PPID       = 0;
    time_t      CreateTime = 0;
    KeyType     KeyType    = PIDOnly;

    bool operator== (const ProcTreeKey &other) const
    {
        switch ( KeyType )
        {
            case KeyType::FullKey:
                return PID == other.PID && PPID == other.PPID && CreateTime == other.CreateTime;
            case KeyType::PIDOnly:
                return PID == other.PID;
            default:
                return false;
        }
        return false;
    }
};

struct ProcTreeKeyHash
{
    size_t operator() (const ProcTreeKey &k) const
    {
        // 与 operator== 一致：PID, PPID, CreateTime 共同决定 Key
        size_t h1 = std::hash<int32_t>()(k.PID);
        size_t h2 = std::hash<int32_t>()(k.PPID);
        size_t h3 = std::hash<time_t>()(k.CreateTime);
        // 组合哈希
        size_t seed = h1;
        seed ^= h2 + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
        return seed;
    }
};

struct EAGLE_THREAT_PROCESS_INFO
{
    int32_t     UtcTime;            // 1
    int32_t     ProcessId;          // 2
    std::string ImagePath;          // 3
    std::string Hash;               // 4
    std::string User;               // 8
    std::string SID;                // 9
    std::string CommandLine;        // 10
    std::string CurrentDirectory;   // 11
    std::string ProcessGuid;        // 14
    std::string ParentProcessGuid;  // 15
    std::string ProcFileId;         // 16
    std::string SignerName;         // 17
    int32_t     CreateTime;         // 19
    int32_t     FileSize;           // 20
    int32_t     SignStatus;         // 21
    std::string fileguid;           // 22
    int32_t     ParentId;
    int32_t     ExitTime;           // 附加不与proto对应
    // 默认构造
    EAGLE_THREAT_PROCESS_INFO();

    // 拷贝构造
    EAGLE_THREAT_PROCESS_INFO(const EAGLE_THREAT_PROCESS_INFO &other);
    // 赋值重载
    EAGLE_THREAT_PROCESS_INFO &operator= (const EAGLE_THREAT_PROCESS_INFO &other);
    // 打印进程信息
    void PrintProcess() const;
};

// 老化队列条目
struct AgingEntry
{
    ProcTreeKey                           key;
    std::chrono::steady_clock::time_point exitTime;
};

class CProcessTree
{
public:
    static CProcessTree *shared();
    
    void StartAging();
    void PrintTree(pid_t iPid, int depth = 0);
    
    bool insertNode(EAGLE_THREAT_PROCESS_INFO *procInfo);
    /// 查询方法
    EAGLE_THREAT_PROCESS_INFO *FindByPid(pid_t pid);
    std::vector<EAGLE_THREAT_PROCESS_INFO *> GetProcessChain(pid_t pid);

    bool markExit(const ProcTreeKey &key);
    
private:
    CProcessTree();
    ~CProcessTree();
    CProcessTree(const CProcessTree &)             = delete;
    CProcessTree &operator= (const CProcessTree &) = delete;
    friend class CProcessThreatDetect;
    
    void deleteNode(EAGLE_THREAT_PROCESS_INFO *procInfo);
    
private:
    std::unordered_map<ProcTreeKey, EAGLE_THREAT_PROCESS_INFO *, ProcTreeKeyHash> m_procTreeMap; //进程树（主映射）
    std::unordered_multimap<int32_t, ProcTreeKey> m_pidIndex; //PID索引（用于快速按PID查找，支持PID复用）
    std::list<AgingEntry> m_agingList; //老化进程列表
    std::thread m_agingThread; //老化线程
    std::mutex m_mutexTree; //进程树锁
    bool m_agingThreadRunning = false; //老化线程运行标志
};


#endif // !CPROCESSTREE_H
