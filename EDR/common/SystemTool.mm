#include <arpa/inet.h>
#include <CommonCrypto/CommonDigest.h>
#include <bsm/libbsm.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <pwd.h>

#include "SystemTool.h"
#include "../module/CProcessTree.h"


time_t GetUtcTime(const es_message_t *msg)  // 获取事件发生的UTC时间
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return 0;
    }

    return msg->time.tv_sec;
}

pid_t GetPid(const es_message_t *msg)  // 获取事件发生的进程id
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return -1;
    }
    const audit_token_t token = msg->process->audit_token;
    pid_t               pid   = audit_token_to_pid(token);
    return pid;
}

pid_t GetPPid(const es_message_t *msg)  // 获取事件发生的进程id
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return -1;
    }
    pid_t ppid = msg->process->ppid;
    return (ppid < 0) ? -1 : ppid;
}

pid_t GetPPid(pid_t pid)
{
    if (pid <= 0)
    {
        return -1;
    }

    struct kinfo_proc procInfo;
    size_t size = sizeof(procInfo);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

    if (sysctl(mib, 4, &procInfo, &size, NULL, 0) != 0)
    {
        // sysctl 失败，可能是无权限或 pid 不存在
        return -1;
    }

    pid_t ppid = procInfo.kp_eproc.e_ppid;
    return (ppid > 0) ? ppid : -1;
}

NSString *GetProcessPath(const es_message_t *msg)
{
    if ( !msg )
    {
        return nil;
    }

    // 只处理 exec 事件
    if ( msg->event_type != ES_EVENT_TYPE_AUTH_EXEC && msg->event_type != ES_EVENT_TYPE_NOTIFY_EXEC )
    {
        return nil;
    }

    const es_process_t *proc = msg->event.exec.target;
    if ( !proc || !proc->executable || !proc->executable->path.data )
    {
        return nil;
    }

    return [NSString stringWithUTF8String:proc->executable->path.data];
}

std::string GetProcessPath(pid_t pid)
{
    if (pid <= 0)
    {
        return std::string();
    }

    char pathbuf[PATH_MAX];
    // proc_pidpath 返回拷贝到 buffer 的长度，失败返回 <= 0
    int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if (ret <= 0)
    {
        // 失败，可能是权限问题或进程已结束
        return std::string();
    }

    // 确保以 std::string 返回
    return std::string(pathbuf);
}

NSString *GetSHA256(const es_message_t *msg)
{
    if ( !msg || !msg->process || !msg->process->executable )
    {
        return nil;
    }

    // 拿到进程可执行文件路径
    const es_file_t *exeFile = msg->process->executable;
    size_t           len     = exeFile->path.length;
    if ( len == 0 )
    {
        return nil;
    }
    char path[PATH_MAX] = { 0 };
    if ( len >= PATH_MAX )
    {
        len = PATH_MAX - 1;
    }
    memcpy(path, exeFile->path.data, len);

    // 打开文件计算 SHA256
    FILE *fp = fopen(path, "rb");
    if ( !fp )
    {
        return nil;
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    unsigned char buffer[4096];
    size_t        bytesRead;
    while ( (bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0 )
    {
        CC_SHA256_Update(&ctx, buffer, (CC_LONG)bytesRead);
    }
    fclose(fp);

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    // 转 hex string
    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        [hashString appendFormat:@"%02x", hash[i]];
    }

    return hashString;
}

NSString *GetSHA256(pid_t pid)
{
    if (pid <= 0)
    {
        return nil;
    }

    char path[PATH_MAX] = {0};
    int ret = proc_pidpath(pid, path, sizeof(path));
    if (ret <= 0)
    {
        // 获取进程路径失败，可能是权限问题或进程已退出
        return nil;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        // 无法打开文件（例如系统进程或权限不足）
        return nil;
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    unsigned char buffer[4096];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        CC_SHA256_Update(&ctx, buffer, (CC_LONG)bytesRead);
    }
    fclose(fp);

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        [hashString appendFormat:@"%02x", hash[i]];
    }

    return hashString;
}

NSString *GetUser(const es_message_t *msg)
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return @"unknown";  // 返回常量字符串，不需要释放
    }

    @autoreleasepool
    {
        // 获取触发事件进程的实际用户 ID
        uid_t uid = GetUid(msg);

        // 转换为用户名
        struct passwd *pw = getpwuid(uid);
        if ( !pw || !pw->pw_name )
        {
            return @"unknown";  // 安全兜底
        }

        // NSString stringWithUTF8String 会返回 autorelease 对象
        NSString *userName = [NSString stringWithUTF8String:pw->pw_name];
        if ( !userName )
        {
            return @"unknown";  // 转换失败兜底
        }

        // 返回 autorelease 对象，外层 autoreleasepool 会托管它的释放
        return userName;
    }
}

NSString *GetUser(pid_t pid)
{
    if (pid <= 0)
    {
        return @"unknown";
    }

    @autoreleasepool
    {
        // 获取进程的实际用户 ID
        uid_t uid = (uid_t)-1;
        int ret = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, NULL, 0);
        if (ret <= 0)
        {
            // 无法通过 proc_pidinfo 获取，使用 fallback 方案
            // 尝试用系统调用 getuid() (仅当 pid 是当前进程)
            if (pid == getpid())
            {
                uid = getuid();
            }
            else
            {
                return @"unknown";
            }
        }
        else
        {
            // proc_pidinfo 成功则使用 getuid_of_pid
            // 但更常见方式是使用 kinfo_proc（sysctl）
            // 所以我们使用更兼容的方式：
            struct kinfo_proc procInfo;
            size_t size = sizeof(procInfo);
            int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
            if (sysctl(mib, 4, &procInfo, &size, NULL, 0) == 0)
            {
                uid = procInfo.kp_eproc.e_ucred.cr_uid;
            }
            else
            {
                return @"unknown";
            }
        }

        if (uid == (uid_t)-1)
        {
            return @"unknown";
        }

        // 根据 UID 获取用户名
        struct passwd *pw = getpwuid(uid);
        if (!pw || !pw->pw_name)
        {
            return @"unknown";
        }

        NSString *userName = [NSString stringWithUTF8String:pw->pw_name];
        if (!userName)
        {
            return @"unknown";
        }

        return userName;
    }
}


uid_t GetUid(const es_message_t *msg)  // 获取事件进程的实际用户 ID
{
    if ( msg == nullptr || msg->process == nullptr )
    {
        return -1;
    }

    const audit_token_t token = msg->process->audit_token;
    uid_t               uid   = audit_token_to_ruid(token);
    return uid;
}

uid_t GetUid(pid_t pid)
{
    if (pid <= 0)
    {
        return (uid_t)-1;
    }

    struct kinfo_proc procInfo;
    size_t size = sizeof(procInfo);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

    if (sysctl(mib, 4, &procInfo, &size, NULL, 0) != 0)
    {
        // sysctl 调用失败，可能是无权限或 pid 不存在
        return (uid_t)-1;
    }

    return procInfo.kp_eproc.e_ucred.cr_uid;
}

NSString *GetCMD(const es_message_t *msg)
{
    if ( !msg || !msg->process )
    {
        return nil;
    }

    // 从 audit_token 里取 PID
    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    if ( pid <= 0 )
    {
        return nil;
    }

    // sysctl MIB
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };

    size_t argmax = 0;
    if ( sysctl(mib, 3, NULL, &argmax, NULL, 0) == -1 )
    {
        return nil;
    }

    char *procargs = (char *)malloc(argmax);
    if ( !procargs )
    {
        return nil;
    }

    if ( sysctl(mib, 3, procargs, &argmax, NULL, 0) == -1 )
    {
        free(procargs);
        return nil;
    }

    // 取 argc
    int argc = 0;
    memcpy(&argc, procargs, sizeof(argc));
    char *p   = procargs + sizeof(argc);
    char *end = procargs + argmax;

    // 跳过 exec path
    while ( p < end && *p != '\0' )
    {
        p++;
    }
    while ( p < end && *p == '\0' )
    {
        p++;
    }

    // argv[0..argc-1]
    NSMutableArray<NSString *> *argvList = [NSMutableArray array];
    for ( int i = 0; i < argc && p < end; i++ )
    {
        NSString *arg = [NSString stringWithUTF8String:p];
        if ( arg )
        {
            [argvList addObject:arg];
        }
        p += strlen(p) + 1;
    }

    free(procargs);

    if ( argvList.count == 0 )
    {
        return nil;
    }

    // 拼接成完整命令行
    return [argvList componentsJoinedByString:@" "];
}

NSString *GetCMD(pid_t pid)
{
    if (pid <= 0)
    {
        return nil;
    }

    // sysctl MIB 定义
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };

    size_t argmax = 0;
    // 第一次 sysctl 获取缓冲区大小
    if (sysctl(mib, 3, NULL, &argmax, NULL, 0) == -1 || argmax == 0)
    {
        return nil;
    }

    char *procargs = (char *)malloc(argmax);
    if (!procargs)
    {
        return nil;
    }

    // 第二次 sysctl 获取实际命令行数据
    if (sysctl(mib, 3, procargs, &argmax, NULL, 0) == -1)
    {
        free(procargs);
        return nil;
    }

    // 取 argc
    int argc = 0;
    memcpy(&argc, procargs, sizeof(argc));
    char *p   = procargs + sizeof(argc);
    char *end = procargs + argmax;

    // 跳过可执行路径
    while (p < end && *p != '\0') p++;
    while (p < end && *p == '\0') p++;

    // 解析 argv[]
    NSMutableArray<NSString *> *argvList = [NSMutableArray array];
    for (int i = 0; i < argc && p < end; i++)
    {
        NSString *arg = [NSString stringWithUTF8String:p];
        if (arg)
        {
            [argvList addObject:arg];
        }
        p += strlen(p) + 1;
    }

    free(procargs);

    if (argvList.count == 0)
    {
        return nil;
    }

    // 拼接成完整命令行字符串
    return [argvList componentsJoinedByString:@" "];
}

NSString *GetPWD(const es_message_t *msg)
{
    if ( !msg || !msg->process )
    {
        return nil;
    }

    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    if ( pid <= 0 )
    {
        return nil;
    }

    struct proc_vnodepathinfo vnodeinfo;
    if ( proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vnodeinfo, sizeof(vnodeinfo)) <= 0 )
    {
        return nil;
    }

    return [NSString stringWithUTF8String:vnodeinfo.pvi_cdir.vip_path];
}

NSString *GetPWD(pid_t pid)
{
    if (pid <= 0)
    {
        return nil;
    }

    struct proc_vnodepathinfo vnodeinfo;
    // 通过 PROC_PIDVNODEPATHINFO 获取进程的当前目录和 root 目录信息
    int ret = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vnodeinfo, sizeof(vnodeinfo));
    if (ret <= 0)
    {
        // 获取失败（例如无权限、进程不存在等）
        return nil;
    }

    // pvi_cdir.vip_path 是当前工作目录（current directory）
    if (vnodeinfo.pvi_cdir.vip_path[0] == '\0')
    {
        return nil;
    }

    return [NSString stringWithUTF8String:vnodeinfo.pvi_cdir.vip_path];
}

NSString *GetGUID(const es_message_t *msg)
{
    if ( !msg || !msg->process )
    {
        return @"";
    }

    // 获取 PID、PPID、进程启动时间
    pid_t pid   = audit_token_to_pid(msg->process->audit_token);
    pid_t ppid  = msg->process->ppid;
    int   ctime = (int)msg->process->start_time.tv_sec;

    if ( pid <= 0 )
    {
        return @"";
    }

    // --- 获取进程镜像路径 ---
    char procPath[PATH_MAX] = { 0 };
    if ( proc_pidpath(pid, procPath, sizeof(procPath)) <= 0 )
    {
        procPath[0] = '\0';
    }

    // --- 获取硬件 UUID ---
    char hardwareUUID[128] = { 0 };
    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if ( ioRegistryRoot )
    {
        CFTypeRef uuidCF = IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        IOObjectRelease(ioRegistryRoot);
        if ( uuidCF && CFGetTypeID(uuidCF) == CFStringGetTypeID() )
        {
            CFStringRef cfStr = (CFStringRef)uuidCF;
            CFStringGetCString(cfStr, hardwareUUID, sizeof(hardwareUUID), kCFStringEncodingUTF8);
        }
        if ( uuidCF )
        {
            CFRelease(uuidCF);
        }
    }

    // --- 拼接唯一标识字符串 ---
    char inputString[PATH_MAX + 256] = { 0 };
    snprintf(inputString, sizeof(inputString), "%d|%d|%d|%s|%s", pid, ppid, ctime, procPath, hardwareUUID);

    // --- 计算 SHA256 ---
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256((const unsigned char *)inputString, (CC_LONG)strlen(inputString), hash);

    // --- 转成 NSString ---
    NSMutableString *guid = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        [guid appendFormat:@"%02x", hash[i]];
    }

    return guid;
}

std::string GetGUID(pid_t pid)
{
    if ( pid <= 0 )
    {
        return "";
    }

    // 获取进程信息（ppid 和启动时间）
    struct proc_bsdinfo info {};
    int                 ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if ( ret <= 0 )
    {
        return "";
    }

    pid_t    ppid       = info.pbi_ppid;
    uint64_t start_time = info.pbi_start_tvsec;

    // 获取进程镜像路径
    char procPath[PATH_MAX] = { 0 };
    if ( proc_pidpath(pid, procPath, sizeof(procPath)) <= 0 )
    {
        procPath[0] = '\0';
    }

    // 获取硬件 UUID
    char                hardwareUUID[128] = { 0 };
    io_registry_entry_t ioRegistryRoot    = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if ( ioRegistryRoot )
    {
        CFTypeRef uuidCF = IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        IOObjectRelease(ioRegistryRoot);
        if ( uuidCF && CFGetTypeID(uuidCF) == CFStringGetTypeID() )
        {
            CFStringGetCString((CFStringRef)uuidCF, hardwareUUID, sizeof(hardwareUUID), kCFStringEncodingUTF8);
        }
        if ( uuidCF )
        {
            CFRelease(uuidCF);
        }
    }

    // 拼接唯一标识字符串
    char inputString[PATH_MAX + 256] = { 0 };
    snprintf(inputString, sizeof(inputString), "%d|%d|%llu|%s|%s", pid, ppid, start_time, procPath, hardwareUUID);

    // 计算 SHA256
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256((const unsigned char *)inputString, (CC_LONG)strlen(inputString), hash);

    // 转成 std::string
    char guidStr[CC_SHA256_DIGEST_LENGTH * 2 + 1] = { 0 };
    for ( int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ )
    {
        snprintf(guidStr + i * 2, 3, "%02x", hash[i]);
    }

    return std::string(guidStr);
}

static std::unordered_map<std::string, std::string> g_signerCache;
static std::mutex                                   g_cacheMutex;
static const size_t                                 kSignerCacheMaxEntries = 390;
// 生成缓存键（路径 + 修改时间）
static std::string MakeCacheKey(const std::string &path)
{
    struct stat st {};
    if ( stat(path.c_str(), &st) != 0 )
    {
        return "";
    }
    std::ostringstream oss;
    oss << path << "_" << st.st_mtime;
    return oss.str();
}
std::string GetSignerName(const std::string &path)
{
    std::string cacheKey = MakeCacheKey(path);

    // 检查缓存
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_signerCache.find(cacheKey);
        if (it != g_signerCache.end())
        {
            return it->second;
        }
    }

    std::string authority;

    // 使用 SecStaticCode + SecStaticCodeCopySigningInformation 获取签名者信息
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path.c_str(), path.size(), false);
    if (!url)
    {
        // 缓存空结果
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_signerCache[cacheKey] = authority;
        return authority;
    }

    SecStaticCodeRef staticCode = nullptr;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess || !staticCode)
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_signerCache[cacheKey] = authority;
        return authority;
    }

    CFDictionaryRef signingInfo = nullptr;
    status = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSDynamicInformation | kSecCSContentInformation, &signingInfo);

    if (status != errSecSuccess || !signingInfo)
    {
        CFRelease(staticCode);
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_signerCache[cacheKey] = authority;
        return authority;
    }

    if (CFGetTypeID(signingInfo) != CFDictionaryGetTypeID())
    {
        CFRelease(signingInfo);
        CFRelease(staticCode);
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_signerCache[cacheKey] = authority;
        return authority;
    }

    // 1. 获取完整的证书链（用箭头连接）
    CFArrayRef certificates = (CFArrayRef)CFDictionaryGetValue(signingInfo, kSecCodeInfoCertificates);
    if (certificates && CFGetTypeID(certificates) == CFArrayGetTypeID())
    {
        CFIndex certCount = CFArrayGetCount(certificates);
        for (CFIndex i = 0; i < certCount; i++)
        {
            SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, i);
            if (cert)
            {
                CFStringRef summary = SecCertificateCopySubjectSummary(cert);
                if (summary)
                {
                    char buff[512] = {0};
                    if (CFStringGetCString(summary, buff, sizeof(buff), kCFStringEncodingUTF8))
                    {
                        if (!authority.empty())
                        {
                            authority += " -> ";
                        }
                        authority += buff;
                    }
                    CFRelease(summary);
                }
            }
        }
    }

    // 2. 获取 TeamIdentifier（用分隔符添加）
    CFStringRef teamID = (CFStringRef)CFDictionaryGetValue(signingInfo, kSecCodeInfoTeamIdentifier);
    if (teamID && CFGetTypeID(teamID) == CFStringGetTypeID())
    {
        char teamBuff[128] = {0};
        if (CFStringGetCString(teamID, teamBuff, sizeof(teamBuff), kCFStringEncodingUTF8))
        {
            if (!authority.empty())
            {
                authority += " | Team=";
            }
            authority += teamBuff;
        }
    }
    else
    {
        // TeamIdentifier 不存在时也要标注
        if (!authority.empty())
        {
            authority += " | Team=not set";
        }
    }

    CFRelease(signingInfo);
    CFRelease(staticCode);

    // 缓存结果
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        if (g_signerCache.size() >= kSignerCacheMaxEntries)
        {
            auto it = g_signerCache.begin();
            if (it != g_signerCache.end())
            {
                g_signerCache.erase(it);
            }
        }
        g_signerCache[cacheKey] = authority;
    }

    return authority;
}

time_t GetCreateTime(const es_message_t *msg)
{
    if (!msg || !msg->process)
    {
        return 0;
    }

    const es_process_t *proc = msg->process;
    
    return static_cast<time_t>(proc->start_time.tv_sec);
}

time_t GetCreateTime(pid_t pid)
{
    if ( pid <= 0 )
    {
        return 0;
    }

    struct proc_bsdinfo info {};
    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if ( ret <= 0 )
    {
        return 0;  // 获取失败
    }

    return static_cast<time_t>(info.pbi_start_tvsec);
}

size_t GetFileSize(pid_t pid)
{
    char pathbuf[PATH_MAX] = { 0 };
    int  ret               = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if ( ret <= 0 )
    {
        // 可选：打印错误信息
        // LOG_ERROR("proc_pidpath failed, errno: {}", errno);
        return -1;
    }

    struct stat st {};
    if ( stat(pathbuf, &st) == 0 )
    {
        return (uint64_t)st.st_size;
    }
    return -1;
}
