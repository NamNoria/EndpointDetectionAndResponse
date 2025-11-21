#ifndef CPROCESSCACHE_H
#define CPROCESSCACHE_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <sys/stat.h>

// 文件信息缓存条目
struct FileInfoCache
{
    std::string value;        // 缓存的值（hash或签名）
    time_t      fileModTime;  // 文件修改时间，用于判断缓存是否有效
    time_t      cacheTime;    // 缓存时间，用于定期清理
};

// 命令行缓存条目
struct CommandLineCache
{
    std::string commandLine;  // 命令行
    time_t      createTime;   // 进程创建时间，用于区分 PID 复用
    time_t      cacheTime;    // 缓存时间
};

/**
 * 进程信息缓存管理器
 * 缓存文件 Hash、代码签名、命令行等耗时操作的结果
 */
class CProcessCache
{
public:
    static CProcessCache* shared();

    // 文件 Hash 缓存
    bool GetFileHash(const std::string& filePath, std::string& outHash);
    void SetFileHash(const std::string& filePath, const std::string& hash);

    // 代码签名缓存
    bool GetSignerName(const std::string& filePath, std::string& outSignerName);
    void SetSignerName(const std::string& filePath, const std::string& signerName);

    // 命令行缓存
    bool GetCommandLine(pid_t pid, time_t createTime, std::string& outCommandLine);
    void SetCommandLine(pid_t pid, time_t createTime, const std::string& commandLine);

    // 清理过期缓存（定期调用）
    void CleanExpiredCache(time_t maxCacheAge = 3600);  // 默认 1 小时过期

    // 清空所有缓存
    void ClearAll();

private:
    CProcessCache();
    ~CProcessCache();
    CProcessCache(const CProcessCache&) = delete;
    CProcessCache& operator=(const CProcessCache&) = delete;

    // 获取文件修改时间
    bool GetFileModTime(const std::string& filePath, time_t& outModTime);

    // 检查缓存大小，超过限制时删除最旧的条目
    void CheckAndLimitCacheSize();

private:
    std::unordered_map<std::string, FileInfoCache> m_hashCache;      // 文件 Hash 缓存
    std::unordered_map<std::string, FileInfoCache> m_signerCache;    // 代码签名缓存
    std::unordered_map<pid_t, CommandLineCache>    m_cmdLineCache;   // 命令行缓存

    std::mutex m_hashMutex;      // Hash 缓存锁
    std::mutex m_signerMutex;    // 签名缓存锁
    std::mutex m_cmdLineMutex;   // 命令行缓存锁

    static constexpr size_t MAX_CACHE_SIZE = 10000;  // 每个缓存最大条目数
};

#endif // CPROCESSCACHE_H
