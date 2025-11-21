#include <chrono>
#include <bsm/libbsm.h>
#include "CProcessThreatDetect.h"
#include "CProcessTree.h"
#include "CFilterRule.h"
#include "../common/Logger.h"
#include "../common/SystemTool.h"

CProcessThreatDetect* CProcessThreatDetect::shared()
{
    static CProcessThreatDetect instance;
    return &instance;
}


/// 处理Auth事件（需要返回决策）
/// @param eventType 事件类型
/// @param message ESF消息
/// @return true允许，false拒绝
bool CProcessThreatDetect::OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in auth handler, event_type={}", static_cast<int>(eventType));
        return true;  // 默认放行
    }

    try
    {
        // 只有case处理此事件
        switch ( message->event_type )
        {
            case ES_EVENT_TYPE_AUTH_EXEC:
                return handleAuthExecEvent(message);
            default:
                return true;
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception in auth event processing: {}, event_type={}", e.what(), static_cast<int>(message->event_type));
        return true;  // 异常时默认放行
    }
    return true;
}

/// 处理Notify事件（仅记录，不拦截）
/// @param eventType 事件类型
/// @param message ESF消息
void CProcessThreatDetect::OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message)
{
//    LOG_INFO("OnNotifyEventReceived");
    if ( !message )
    {
        LOG_ERROR("Received null message in notify handler, event_type={}", static_cast<int>(eventType));
        return;
    }

    try
    {
        switch ( message->event_type )
        {
            case ES_EVENT_TYPE_NOTIFY_EXIT:
//                LOG_INFO("ES_EVENT_TYPE_NOTIFY_EXIT");
                handleNotifyExitEvent(message);
                break;
            case ES_EVENT_TYPE_NOTIFY_FORK:
                handleNotifyForkEvent(message);
                break;
            default:
                break;
        }
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception in notify event processing: {}, event_type={}", e.what(), static_cast<int>(eventType));
    }
}

/// 获取本模块关心的事件类型（自注册）
std::vector<es_event_type_t> CProcessThreatDetect::GetSubscribedEventTypes()
{
    return { ES_EVENT_TYPE_AUTH_EXEC,   // 进程执行
             ES_EVENT_TYPE_NOTIFY_EXIT,  // 进程退出
             ES_EVENT_TYPE_NOTIFY_FORK }; // 进程fork
}

CProcessThreatDetect::CProcessThreatDetect()
    : m_missedProcessCount(0)
    , m_lastReportTime(std::chrono::steady_clock::now())
{
    CFilterRule::shared();
}

CProcessThreatDetect::~CProcessThreatDetect()
{
    
}

bool CProcessThreatDetect::handleAuthExecEvent(const es_message_t *message)
{
    // 1、入参检查
    if ( message == nullptr || message->event_type != ES_EVENT_TYPE_AUTH_EXEC )
    {
        LOG_ERROR("Invalid message for AUTH_EXEC event: message is null");
        return true;// 放行
    }
    
    EAGLE_THREAT_PROCESS_INFO *pProcessInfo = nullptr;
    
    try
    {
        pProcessInfo = new EAGLE_THREAT_PROCESS_INFO();
        pProcessInfo->UtcTime = (int32_t)GetUtcTime(message);
        pProcessInfo->ProcessId = GetPid(message);
        pProcessInfo->CreateTime = (int32_t)GetCreateTime(message);

        NSString *processPath = GetProcessPath(message);
        pProcessInfo->ImagePath = processPath ? [processPath UTF8String] : "";

        NSString *hash = GetSHA256(message);
        pProcessInfo->Hash = hash ? [hash UTF8String] : "";

        NSString *user = GetUser(message);
        pProcessInfo->User = user ? [user UTF8String] : "unknown";

        pProcessInfo->SID = std::to_string(GetUid(message));

        NSString *cmd = GetCMD(message);
        pProcessInfo->CommandLine = cmd ? [cmd UTF8String] : "";

        NSString *pwd = GetPWD(message);
        pProcessInfo->CurrentDirectory = pwd ? [pwd UTF8String] : "";

        pProcessInfo->ProcessGuid = GetGUID(pProcessInfo->ProcessId);
        pProcessInfo->ParentProcessGuid = GetGUID(GetPPid(message));
        pProcessInfo->ParentId = GetPPid(message);
        pProcessInfo->SignerName = GetSignerName(pProcessInfo->ImagePath);

        pProcessInfo->FileSize = (int32_t)GetFileSize(GetPid(message));
        pProcessInfo->SignStatus = 0;
//        pProcessInfo->PrintProcess();
        
        // 2、加入进程树
        CProcessTree* pProcessTree = CProcessTree::shared();
        if(!pProcessTree)
        {
            LOG_ERROR("Failed to get ProcessTree instance");
            delete pProcessInfo;
            return true;// 放行
        }
        
        pProcessTree->insertNode(pProcessInfo);

        // 3、自过滤
        CFilterRule *pFilter = CFilterRule::shared();

        // 4、检查过滤
        THREAT_PROC_INFO *pEventInfo = nullptr;
        THREAT_PROC_INFO *pParentInfo = nullptr;
        std::string outThreatInfo;
        if(pFilter)
        {
            pFilter->ProcessFilterAllow(pEventInfo, pParentInfo, &outThreatInfo);
        }
        else
        {
            LOG_WARN("Filter rule instance is null, skipping filter check");
        }

        // 5、序列化Protobuf

        // 6、添加队列上报

        // 7、释放临时对象（insertNode 已经复制了数据）
        delete pProcessInfo;
        pProcessInfo = nullptr;

        return true;
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Exception in handleAuthExecEvent: {}", e.what());
        if (pProcessInfo)
        {
            delete pProcessInfo;
        }
        return true; // 异常时默认放行
    }
    catch (...)
    {
        LOG_ERROR("Unknown exception in handleAuthExecEvent");
        if (pProcessInfo)
        {
            delete pProcessInfo;
        }
        return true; // 异常时默认放行
    }
}

void CProcessThreatDetect::handleNotifyExitEvent(const es_message_t *message)
{
    // 1、入参检查
    if ( !message || message->event_type != ES_EVENT_TYPE_NOTIFY_EXIT )
    {
        return;
    }

    // 2、获取退出进程的基础信息
    CProcessTree* pProcessTree = CProcessTree::shared();
    if(!pProcessTree)
    {
        return;
    }

    // 3、从进程树中查找进程并标记退出
    pid_t exitPid = GetPid(message);
    EAGLE_THREAT_PROCESS_INFO* pProcInfo = pProcessTree->FindByPid(exitPid);

    if(pProcInfo)
    {
        // 进程在树中，标记退出并加入老化队列（延迟删除）
        ProcTreeKey exitProcessKey;
        exitProcessKey.PID = exitPid;
        exitProcessKey.PPID = pProcInfo->ParentId;
        exitProcessKey.CreateTime = pProcInfo->CreateTime;
        exitProcessKey.KeyType = ProcTreeKey::FullKey;

        pProcessTree->markExit(exitProcessKey);

        LOG_DEBUG("Process exited and marked for aging, PID={}, Path={}",
                  exitPid, pProcInfo->ImagePath);
    }
    else
    {
        // 进程不在树中，说明之前未被跟踪（可能错过了 EXEC/FORK 事件）
        // 不尝试插入树，只记录日志和统计
        m_missedProcessCount++;

        // 尽力从 message 中获取基本信息用于日志（仅用于调试）
        std::string imagePath = "unknown";
        const es_process_t *proc = message->process;
        if (proc && proc->executable && proc->executable->path.data)
        {
            imagePath = std::string(proc->executable->path.data, proc->executable->path.length);
        }

        LOG_DEBUG("Process exit event for untracked process, PID={}, Path={}",
                  exitPid, imagePath);

        // 定期统计报告
        std::lock_guard<std::mutex> lock(m_statsMutex);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastReportTime).count();

        if (elapsed >= 30)  // 每30秒报告一次
        {
            uint64_t count = m_missedProcessCount.exchange(0);
            if (count > 0)
            {
                LOG_INFO("Process exit summary: {} processes were not tracked (last 30s)", count);
            }
            m_lastReportTime = now;
        }
    }
}

void CProcessThreatDetect::handleNotifyForkEvent(const es_message_t *message)
{
    // 1、入参检查
    if ( !message || message->event_type != ES_EVENT_TYPE_NOTIFY_FORK )
    {
        return;
    }

    // 2、获取子进程信息
    const es_process_t *child = message->event.fork.child;
    if ( !child )
    {
        LOG_ERROR("NOTIFY_FORK event has null child process");
        return;
    }

    EAGLE_THREAT_PROCESS_INFO *pProcessInfo = nullptr;

    try
    {
        pProcessInfo = new EAGLE_THREAT_PROCESS_INFO();

        // 获取子进程的审计令牌
        pid_t childPid = audit_token_to_pid(child->audit_token);
        pProcessInfo->ProcessId = childPid;
        pProcessInfo->ParentId = child->ppid;
        pProcessInfo->CreateTime = (int32_t)child->start_time.tv_sec;
        pProcessInfo->UtcTime = (int32_t)message->time.tv_sec;

        // 获取进程路径
        if ( child->executable && child->executable->path.data )
        {
            pProcessInfo->ImagePath = std::string(child->executable->path.data, child->executable->path.length);
        }
        else
        {
            // Fork 后可能还没有 exec，使用父进程路径
            pProcessInfo->ImagePath = GetProcessPath(childPid);
        }

        // 获取其他信息（使用 pid 查询）
        NSString *hash = GetSHA256(childPid);
        pProcessInfo->Hash = hash ? [hash UTF8String] : "";

        NSString *user = GetUser(childPid);
        pProcessInfo->User = user ? [user UTF8String] : "unknown";

        pProcessInfo->SID = std::to_string(audit_token_to_ruid(child->audit_token));

        NSString *cmd = GetCMD(childPid);
        pProcessInfo->CommandLine = cmd ? [cmd UTF8String] : "";

        NSString *pwd = GetPWD(childPid);
        pProcessInfo->CurrentDirectory = pwd ? [pwd UTF8String] : "";

        pProcessInfo->ProcessGuid = GetGUID(childPid);
        pProcessInfo->ParentProcessGuid = GetGUID(pProcessInfo->ParentId);
        pProcessInfo->SignerName = GetSignerName(pProcessInfo->ImagePath);
        pProcessInfo->FileSize = (int32_t)GetFileSize(childPid);
        pProcessInfo->SignStatus = 0;

        // 3、加入进程树
        CProcessTree* pProcessTree = CProcessTree::shared();
        if ( !pProcessTree )
        {
            LOG_ERROR("Failed to get ProcessTree instance in fork handler");
            delete pProcessInfo;
            return;
        }

        pProcessTree->insertNode(pProcessInfo);
        LOG_DEBUG("NOTIFY_FORK: Process added to tree, PID={}, PPID={}, Path={}",
                 childPid, pProcessInfo->ParentId, pProcessInfo->ImagePath);

        // 4、释放临时对象（insertNode 已经复制了数据）
        delete pProcessInfo;
        pProcessInfo = nullptr;
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Exception in handleNotifyForkEvent: {}", e.what());
        if (pProcessInfo)
        {
            delete pProcessInfo;
        }
    }
    catch (...)
    {
        LOG_ERROR("Unknown exception in handleNotifyForkEvent");
        if (pProcessInfo)
        {
            delete pProcessInfo;
        }
    }
}
