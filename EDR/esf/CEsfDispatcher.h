#ifndef CESFDISPATCHER_H
#define CESFDISPATCHER_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <queue>
#include <map>
#include "../common/macro.h"


struct ESFEvent
{
    es_client_t        *client;  // 只存指针，不拷贝
    const es_message_t *message;
};

class IESFEventObserver;
class CEsfDispatcher
{
public:
    static CEsfDispatcher *shared();
    
    static void PushNotifyEvent(ESFEvent *message);
    static void PushAuthEvent(ESFEvent *message);
    
    void SubscribeEvent(es_event_type_t eventType, IESFEventObserver *observer);

private:
    CEsfDispatcher();
    ~CEsfDispatcher();
    
    //事件处理回调
    static void handleNotifyEvent(es_client_t *client, const es_message_t *message);
    static void handleAuthEvent(es_client_t *client, const es_message_t *message);
    
    //派发事件
    void dispatchNotifyEvent(es_event_type_t eventType, const es_message_t *message);
    bool dispatchAuthEvent(es_event_type_t eventType, const es_message_t *message);
    
    //派发线程函数
    static void *dispatchNotifyThreadFunc(void *arg);
    static void *authWorkerThreadFunc(void *arg);
public:
    std::mutex  m_subscriptionMutex;   // 订阅互斥锁
    std::map<es_event_type_t, std::vector<IESFEventObserver *>> m_eventSubscriptions;  // 事件订阅映射
private:
    // Notify单线程
    pthread_t m_dispatchNotifyThread;

    // Auth线程池
    static size_t kAuthThreadPoolSize;  // 可配置的Auth线程数
    std::vector<pthread_t> m_authThreadPool;
    
    static pthread_mutex_t        m_queNotifyMutex;
    static pthread_mutex_t        m_queAuthMutex;
    static pthread_cond_t         m_queNotifyCond;
    static pthread_cond_t         m_queAuthCond;
    
    static std::queue<ESFEvent *> m_queNotifyEvent;  // 事件队列TODO：无锁队列
    static std::queue<ESFEvent *> m_queAuthEvent;    // 事件队列TODO：无锁队列
    
    static std::atomic<uint64_t> m_authEventsProcessed;
    static std::atomic<uint64_t> m_notifyEventsProcessed;
};
#endif // !CESFDISPATCHER_H
