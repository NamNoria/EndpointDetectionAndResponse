#include "CProcessCache.h"
#include "Logger.h"
#include <sys/stat.h>
#include <algorithm>
#include <vector>

CProcessCache* CProcessCache::shared()
{
    static CProcessCache instance;
    return &instance;
}

CProcessCache::CProcessCache()
{
    LOG_INFO("CProcessCache initialized");
}

CProcessCache::~CProcessCache()
{
    ClearAll();
}

bool CProcessCache::GetFileModTime(const std::string& filePath, time_t& outModTime)
{
    struct stat fileStat;
    if (stat(filePath.c_str(), &fileStat) == 0)
    {
        outModTime = fileStat.st_mtime;
        return true;
    }
    return false;
}

// ========== 文件 Hash 缓存 ==========

bool CProcessCache::GetFileHash(const std::string& filePath, std::string& outHash)
{
    if (filePath.empty())
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_hashMutex);

    auto it = m_hashCache.find(filePath);
    if (it == m_hashCache.end())
    {
        return false;  // 缓存未命中
    }

    // 检查文件是否被修改
    time_t currentModTime = 0;
    if (!GetFileModTime(filePath, currentModTime))
    {
        // 文件不存在，删除缓存
        m_hashCache.erase(it);
        return false;
    }

    if (it->second.fileModTime != currentModTime)
    {
        // 文件已修改，缓存失效
        m_hashCache.erase(it);
        return false;
    }

    // 缓存命中且有效
    outHash = it->second.value;
    return true;
}

void CProcessCache::SetFileHash(const std::string& filePath, const std::string& hash)
{
    if (filePath.empty() || hash.empty())
    {
        return;
    }

    time_t modTime = 0;
    if (!GetFileModTime(filePath, modTime))
    {
        return;  // 文件不存在，不缓存
    }

    std::lock_guard<std::mutex> lock(m_hashMutex);

    FileInfoCache cache;
    cache.value = hash;
    cache.fileModTime = modTime;
    cache.cacheTime = time(nullptr);

    m_hashCache[filePath] = cache;

    // 检查缓存大小
    if (m_hashCache.size() > MAX_CACHE_SIZE)
    {
        // 删除最旧的条目
        auto oldestIt = m_hashCache.begin();
        time_t oldestTime = oldestIt->second.cacheTime;

        for (auto it = m_hashCache.begin(); it != m_hashCache.end(); ++it)
        {
            if (it->second.cacheTime < oldestTime)
            {
                oldestTime = it->second.cacheTime;
                oldestIt = it;
            }
        }
        m_hashCache.erase(oldestIt);
        LOG_DEBUG("Hash cache size limit reached, removed oldest entry");
    }
}

// ========== 代码签名缓存 ==========

bool CProcessCache::GetSignerName(const std::string& filePath, std::string& outSignerName)
{
    if (filePath.empty())
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_signerMutex);

    auto it = m_signerCache.find(filePath);
    if (it == m_signerCache.end())
    {
        return false;  // 缓存未命中
    }

    // 检查文件是否被修改
    time_t currentModTime = 0;
    if (!GetFileModTime(filePath, currentModTime))
    {
        // 文件不存在，删除缓存
        m_signerCache.erase(it);
        return false;
    }

    if (it->second.fileModTime != currentModTime)
    {
        // 文件已修改，缓存失效
        m_signerCache.erase(it);
        return false;
    }

    // 缓存命中且有效
    outSignerName = it->second.value;
    return true;
}

void CProcessCache::SetSignerName(const std::string& filePath, const std::string& signerName)
{
    if (filePath.empty())
    {
        return;
    }

    // 签名为空也缓存（表示未签名）
    time_t modTime = 0;
    if (!GetFileModTime(filePath, modTime))
    {
        return;  // 文件不存在，不缓存
    }

    std::lock_guard<std::mutex> lock(m_signerMutex);

    FileInfoCache cache;
    cache.value = signerName;
    cache.fileModTime = modTime;
    cache.cacheTime = time(nullptr);

    m_signerCache[filePath] = cache;

    // 检查缓存大小
    if (m_signerCache.size() > MAX_CACHE_SIZE)
    {
        // 删除最旧的条目
        auto oldestIt = m_signerCache.begin();
        time_t oldestTime = oldestIt->second.cacheTime;

        for (auto it = m_signerCache.begin(); it != m_signerCache.end(); ++it)
        {
            if (it->second.cacheTime < oldestTime)
            {
                oldestTime = it->second.cacheTime;
                oldestIt = it;
            }
        }
        m_signerCache.erase(oldestIt);
        LOG_DEBUG("Signer cache size limit reached, removed oldest entry");
    }
}

// ========== 命令行缓存 ==========

bool CProcessCache::GetCommandLine(pid_t pid, time_t createTime, std::string& outCommandLine)
{
    if (pid <= 0)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_cmdLineMutex);

    auto it = m_cmdLineCache.find(pid);
    if (it == m_cmdLineCache.end())
    {
        return false;  // 缓存未命中
    }

    // 检查是否是同一个进程（避免 PID 复用）
    if (it->second.createTime != createTime)
    {
        // PID 被复用，缓存失效
        m_cmdLineCache.erase(it);
        return false;
    }

    // 缓存命中且有效
    outCommandLine = it->second.commandLine;
    return true;
}

void CProcessCache::SetCommandLine(pid_t pid, time_t createTime, const std::string& commandLine)
{
    if (pid <= 0)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(m_cmdLineMutex);

    CommandLineCache cache;
    cache.commandLine = commandLine;
    cache.createTime = createTime;
    cache.cacheTime = time(nullptr);

    m_cmdLineCache[pid] = cache;

    // 检查缓存大小
    if (m_cmdLineCache.size() > MAX_CACHE_SIZE)
    {
        // 删除最旧的条目
        auto oldestIt = m_cmdLineCache.begin();
        time_t oldestTime = oldestIt->second.cacheTime;

        for (auto it = m_cmdLineCache.begin(); it != m_cmdLineCache.end(); ++it)
        {
            if (it->second.cacheTime < oldestTime)
            {
                oldestTime = it->second.cacheTime;
                oldestIt = it;
            }
        }
        m_cmdLineCache.erase(oldestIt);
        LOG_DEBUG("CommandLine cache size limit reached, removed oldest entry");
    }
}

// ========== 缓存清理 ==========

void CProcessCache::CleanExpiredCache(time_t maxCacheAge)
{
    time_t now = time(nullptr);
    size_t hashRemoved = 0;
    size_t signerRemoved = 0;
    size_t cmdLineRemoved = 0;

    // 清理 Hash 缓存
    {
        std::lock_guard<std::mutex> lock(m_hashMutex);
        for (auto it = m_hashCache.begin(); it != m_hashCache.end(); )
        {
            if (now - it->second.cacheTime > maxCacheAge)
            {
                it = m_hashCache.erase(it);
                hashRemoved++;
            }
            else
            {
                ++it;
            }
        }
    }

    // 清理签名缓存
    {
        std::lock_guard<std::mutex> lock(m_signerMutex);
        for (auto it = m_signerCache.begin(); it != m_signerCache.end(); )
        {
            if (now - it->second.cacheTime > maxCacheAge)
            {
                it = m_signerCache.erase(it);
                signerRemoved++;
            }
            else
            {
                ++it;
            }
        }
    }

    // 清理命令行缓存
    {
        std::lock_guard<std::mutex> lock(m_cmdLineMutex);
        for (auto it = m_cmdLineCache.begin(); it != m_cmdLineCache.end(); )
        {
            if (now - it->second.cacheTime > maxCacheAge)
            {
                it = m_cmdLineCache.erase(it);
                cmdLineRemoved++;
            }
            else
            {
                ++it;
            }
        }
    }

    if (hashRemoved > 0 || signerRemoved > 0 || cmdLineRemoved > 0)
    {
        LOG_INFO("CleanExpiredCache: removed {} hash, {} signer, {} cmdline entries",
                 hashRemoved, signerRemoved, cmdLineRemoved);
    }
}

void CProcessCache::ClearAll()
{
    {
        std::lock_guard<std::mutex> lock(m_hashMutex);
        m_hashCache.clear();
    }

    {
        std::lock_guard<std::mutex> lock(m_signerMutex);
        m_signerCache.clear();
    }

    {
        std::lock_guard<std::mutex> lock(m_cmdLineMutex);
        m_cmdLineCache.clear();
    }

    LOG_INFO("All caches cleared");
}

void CProcessCache::CheckAndLimitCacheSize()
{
    // 这个方法已经在 Set 方法中内联处理了
}
