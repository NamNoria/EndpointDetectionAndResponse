#include "CInstallerDetect.h"
#include "../common/Logger.h"

CInstallerDetect* CInstallerDetect::shared()
{
    static CInstallerDetect instance;
    return &instance;
}

/// 处理Auth事件（需要返回决策）
/// @param eventType 事件类型
/// @param message ESF消息
/// @return true允许，false拒绝
bool CInstallerDetect::OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    if (!message)
    {
        return true;
    }

    switch (eventType)
    {
        case ES_EVENT_TYPE_AUTH_MOUNT:
            return handleAuthMountEvent(message);
        default:
            return true;
    }
    return true;
}

/// 处理Notify事件（仅记录，不拦截）
/// @param eventType 事件类型
/// @param message ESF消息
void CInstallerDetect::OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message)
{
    return;
}

/// 获取本模块关心的事件类型（自注册）
std::vector<es_event_type_t> CInstallerDetect::GetSubscribedEventTypes()
{
    return {ES_EVENT_TYPE_AUTH_MOUNT};
}

CInstallerDetect::CInstallerDetect()
{
    
}

CInstallerDetect::~CInstallerDetect()
{
    
}

bool CInstallerDetect::handleAuthMountEvent(const es_message_t *message)
{
    if (!message || message->event_type != ES_EVENT_TYPE_AUTH_MOUNT)
    {
        return true;
    }
    // TODO: 实现安装包挂载检测逻辑
    LOG_INFO("handleAuthMountEvent");
    return true;
}
