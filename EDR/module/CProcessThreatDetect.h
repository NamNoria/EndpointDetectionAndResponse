#ifndef CPROCESSTHREATDETECT_T
#define CPROCESSTHREATDETECT_T

#include <atomic>
#include <chrono>
#include <mutex>
#include "IESFEventObserver.h"
#include "../common/macro.h"

class CProcessThreatDetect: public IESFEventObserver
{
public:
    static CProcessThreatDetect *shared();

    /// 处理Auth事件（需要返回决策）
    /// @param eventType 事件类型
    /// @param message ESF消息
    /// @return true允许，false拒绝
    bool OnAuthEventReceived(es_event_type_t eventType, const es_message_t *message) override;

    /// 处理Notify事件（仅记录，不拦截）
    /// @param eventType 事件类型
    /// @param message ESF消息
    void OnNotifyEventReceived(es_event_type_t eventType, const es_message_t *message) override;

    /// 获取本模块关心的事件类型（自注册）
    std::vector<es_event_type_t> GetSubscribedEventTypes() override;
private:
    CProcessThreatDetect();
    ~CProcessThreatDetect();
    bool handleAuthExecEvent(const es_message_t *message);
    void handleNotifyExitEvent(const es_message_t *message);
    void handleNotifyForkEvent(const es_message_t *message);

    // 统计找不到的进程
    std::atomic<uint64_t> m_missedProcessCount{0};
    std::chrono::steady_clock::time_point m_lastReportTime;
    std::mutex m_statsMutex;
};

#endif // !CPROCESSTHREATDETECT_T
