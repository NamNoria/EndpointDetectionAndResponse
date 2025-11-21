#include "CFileThreatDetect.h"
#include "CFilterRule.h"
//#include "CThreatEvent.h"
#include "CProcessTree.h"
#include "../common/Logger.h"
#include "../CThreatDetect.h"

CFileThreatDetect*CFileThreatDetect::shared()
{
    static CFileThreatDetect instance;
    return &instance;
}

bool CFileThreatDetect::OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if (!message)
    {
        return true;
    }

    switch (eventType)
    {
        case ES_EVENT_TYPE_AUTH_CREATE:
            return handleAuthCreateEvent(message);
        case ES_EVENT_TYPE_AUTH_RENAME:
            return handleAuthRenameEvent(message);
        default:
            return true;
    }
    return true;
}

void CFileThreatDetect::OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if (!message)
    {
        return;
    }

    switch (eventType)
    {
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            handleNotifyCloseEvent(message);
            break;
        default:
            break;
    }
}

std::vector<es_event_type_t> CFileThreatDetect::GetSubscribedEventTypes()
{
    // 文件威胁检测订阅文件相关事件，不包括 MOUNT（MOUNT 在 CInstallerDetect 中）
    return {
        ES_EVENT_TYPE_AUTH_CREATE,   // 文件创建（暂未启用）
        ES_EVENT_TYPE_AUTH_RENAME,   // 文件重命名（暂未启用）
        ES_EVENT_TYPE_NOTIFY_CLOSE   // 文件关闭（暂未启用）
    };
}

CFileThreatDetect::CFileThreatDetect()
{

}

CFileThreatDetect::~CFileThreatDetect()
{

}

bool CFileThreatDetect::handleAuthCreateEvent(const es_message_t *message)
{
    if (!message || !message->process || message->event_type != ES_EVENT_TYPE_AUTH_CREATE)
    {
        return true;
    }
//    LOG_INFO("handleAuthCreateEvent");
    return true;
}

bool CFileThreatDetect::handleAuthRenameEvent(const es_message_t *message)
{
    if (!message || message->event_type != ES_EVENT_TYPE_AUTH_RENAME)
    {
        return true;
    }
//    LOG_INFO("handleAuthRenameEvent");
    return true;
}

void CFileThreatDetect::handleNotifyCloseEvent(const es_message_t *message)
{
    if (!message || message->event_type != ES_EVENT_TYPE_NOTIFY_CLOSE)
    {
        return;
    }
//    LOG_INFO("handleNotifyCloseEvent");
}
