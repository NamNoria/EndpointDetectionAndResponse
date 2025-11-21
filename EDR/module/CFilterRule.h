#ifndef CFILTERRULE_H
#define CFILTERRULE_H

#include <string>
#include <vector>
#include <map>
#include <typeindex>

// Rust动态库相关类型声明（需与实现文件一致）
enum ActionStatus
{
    RULE_ACTION_PASS   = 0,
    RULE_ACTION_BLOCK  = 2,
    RULE_ACTION_REPORT = 4,
    RULE_ACTION_FILTER = 7,
};

struct THREAT_PROC_INFO
{
    char    *guid;
    char    *image;
    char    *cmd;
    char    *pwd;
    char    *sha256;
    char    *signer;
    char    *orig_file;
    char    *company;
    char    *parent_guid;
    uint32_t integrity;
    uint32_t pid;
    char    *source;
};

struct FILE_CREATE_INFO
{
    const char *filepath;
    int         create_options;
};

struct FILE_RENAME_INFO
{
    const char *old_filepath;
    const char *new_filepath;
};

struct BehaviorResult
{
    int         action;
    int         popu;
    const char *event_info;
    const char *threat_info;
    const char *pop_info;
};

/// 静默进程规则
struct SilentProcessRule
{
    std::string process;         // 进程名（精确匹配）
    pid_t       pid;             // 预留字段：指定PID（0表示忽略）
    pid_t       ppid;            // 预留字段：指定父PID（0表示忽略）
    uint64_t    silentStartUtc;  // 静默开始时间（UTC秒，0表示立即生效）
    uint64_t    silentDuration;  // 静默持续秒数（0表示永久）
    std::string description;     // 描述

    /// 判断当前进程是否匹配过滤规则（当前只按进程名匹配）
    bool Matches(const std::string &procName) const;
};

/// 文件过滤规则
struct FileFilterRule
{
    std::string srcPath;         // 源路径（精确匹配）
    std::string dstPath;         // 目标路径（精确匹配）
    uint64_t    silentStartUtc;  // 静默开始时间（UTC秒，0表示立即生效）
    uint64_t    silentDuration;  // 静默持续秒数（0表示永久）
    std::string description;     // 描述

    /// 判断当前文件是否匹配过滤规则
    bool Matches(const std::string &strSrcPath, const std::string &strDstPath) const;
};

/// EDR 总过滤规则
struct FilterRuleData
{
    std::string                    version;          // 配置版本
    uint64_t                       lastUpdated;      // 最后更新时间（UTC秒）
    std::vector<SilentProcessRule> silentProcesses;  // 进程过滤规则
    std::vector<FileFilterRule>    fileFilters;      // 文件过滤规则
    // std::vector<NetFilterRule>     netFilters;       // 网络过滤规则

    void Clear();
};

typedef bool (*init_fn)(const char *token, const char *server_host);
typedef int (*onfilecreate_fn)(const char *, const struct THREAT_PROC_INFO *, const struct FILE_CREATE_INFO *, const struct BehaviorResult **);
typedef int (*onfilerename_fn)(const char *, const struct THREAT_PROC_INFO *, const struct FILE_RENAME_INFO *, const struct BehaviorResult **);
typedef int (*onprocstart_fn)(const char *, const struct THREAT_PROC_INFO *, const struct THREAT_PROC_INFO *, const struct BehaviorResult **);
typedef void (*freeresult_fn)(struct BehaviorResult *);

class CFilterRule
{
public:
    static CFilterRule *shared();
    bool IsConfigLoaded();
    
    ActionStatus FileRenameFilterAllow(FILE_RENAME_INFO *pEventInfo, THREAT_PROC_INFO* pProcInfo, std::string *outThreatInfo) const;
    ActionStatus FileCreateFilterAllow(FILE_CREATE_INFO *pEventInfo, THREAT_PROC_INFO* pProcInfo, std::string *outThreatInfo) const;
    ActionStatus ProcessFilterAllow(THREAT_PROC_INFO *pEventInfo, THREAT_PROC_INFO *pParentInfo, std::string *outThreatInfo) const;

private:
    CFilterRule();
    ~CFilterRule();
#pragma mark -libfunc
    static init_fn         m_initengine_macos;
    static onfilecreate_fn m_onfilecreate;
    static onfilerename_fn m_onfilerename;
    static onprocstart_fn  m_onprocstart;
    static freeresult_fn   m_freeresult;
};
#endif // !CFILTERRULE_H
