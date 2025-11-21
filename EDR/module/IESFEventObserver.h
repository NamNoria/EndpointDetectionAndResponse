#ifndef IESFEVENTOBSERVER_H
#define IESFEVENTOBSERVER_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <vector>

/**
 * @brief 事件观察者接口
 *
 */
class IESFEventObserver
{
public:
    virtual ~IESFEventObserver() = default;

    /// 处理Auth事件（需要返回决策）
    /// @param eventType 事件类型
    /// @param message ESF消息
    /// @return true允许，false拒绝
    virtual bool OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message) = 0;

    /// 处理Notify事件（仅记录，不拦截）
    /// @param eventType 事件类型
    /// @param message ESF消息
    virtual void OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message) = 0;

    /// 获取本模块关心的事件类型
    virtual std::vector<es_event_type_t> GetSubscribedEventTypes() = 0;
};

#endif // !IESFEVENTOBSERVER_H
