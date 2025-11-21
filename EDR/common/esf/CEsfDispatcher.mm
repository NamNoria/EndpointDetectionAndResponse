#include "CEsfDispatcher.h"
#include "../common/Logger.h"
#include "../module/IESFEventObserver.h"
#include <libproc.h>
#include <bsm/libbsm.h>

std::atomic<uint64_t> CEsfDispatcher::m_authEventsProcessed{0};
std::atomic<uint64_t> CEsfDispatcher::m_notifyEventsProcessed{0};
size_t CEsfDispatcher::kAuthThreadPoolSize = 4;

#pragma mark -TOOL

// 从完整路径中提取进程名
static std::string extractProcessName(const std::string& path)
{
    if (path.empty())
    {
        return "";
    }

    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos)
    {
        return path;
    }
    return path.substr(pos + 1);
}

// 通过 PID 获取进程路径
static std::string getProcessPathByPid(pid_t pid)
{
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};

    int ret = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
    if (ret <= 0)
    {
        LOG_WARN("Failed to get process path for pid={}, error={}", pid, errno);
        return "";
    }

    return std::string(pathBuffer);
}

// 判断是否是编译器进程
// 参数: pid - 进程ID
// 返回: true 表示是编译器进程，false 表示不是
static bool isCompilerProcess(pid_t pid)
{
    // 获取进程路径
    std::string processPath = getProcessPathByPid(pid);
    if (processPath.empty())
    {
        return false;
    }

    // 提取进程名
    std::string processName = extractProcessName(processPath);
    if (processName.empty())
    {
        return false;
    }

    // 常见的编译器和构建工具列表
    static const std::vector<std::string> compilerNames = {
        // C/C++ 编译器
        "clang", "clang++", "cc", "c++",
        "gcc", "g++",
        "ld",           // 链接器
        "as",           // 汇编器
        "strip",        // 符号剥离工具

        // Swift
        "swift", "swiftc",

        // Xcode 相关
        "xcodebuild",
        "xcrun",

        // 构建工具
        "make", "gmake",
        "cmake",
        "ninja",
        "bazel",

        // 其他语言编译器
        "javac",        // Java
        "rustc",        // Rust
        "go",           // Go
        "cargo",        // Rust 构建工具
        "npm", "yarn",  // JavaScript 构建工具
        "mvn", "gradle" // Java 构建工具
    };

    // 检查进程名是否在编译器列表中
    for (const auto& compiler : compilerNames)
    {
        if (processName == compiler)
        {
            LOG_DEBUG("Detected compiler process: pid={}, name={}, path={}",
                     pid, processName, processPath);
            return true;
        }
    }

    return false;
}


#pragma mark -BODY
pthread_mutex_t        CEsfDispatcher::m_queNotifyMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t        CEsfDispatcher::m_queAuthMutex   = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t         CEsfDispatcher::m_queNotifyCond  = PTHREAD_COND_INITIALIZER;
pthread_cond_t         CEsfDispatcher::m_queAuthCond    = PTHREAD_COND_INITIALIZER;
std::queue<ESFEvent *> CEsfDispatcher::m_queNotifyEvent;
std::queue<ESFEvent *> CEsfDispatcher::m_queAuthEvent;
CEsfDispatcher *CEsfDispatcher::shared()
{
    static CEsfDispatcher instance;
    return &instance;
}

void CEsfDispatcher::PushNotifyEvent(ESFEvent *message)
{
    if (!message || !message->message)
    {
        return;
    }
    
//    if( ES_EVENT_TYPE_NOTIFY_CLOSE == message->message->event_type )
//    {
//        const audit_token_t token = message->message->process->audit_token;
//        pid_t               pid   = audit_token_to_pid(token);
//        if(isCompilerProcess(pid))
//        {
//            es_release_message(message->message);
//            free(message);
//            return;
//        }
//    }
    
    pthread_mutex_lock(&m_queNotifyMutex);
    if (m_queNotifyEvent.size() >= NOTIFYEVENT_QUESIZE)
    {
        ESFEvent *oldEvent = m_queNotifyEvent.front();
        m_queNotifyEvent.pop();
        es_release_message(oldEvent->message);
        free(oldEvent);
    }
    m_queNotifyEvent.push(message);
    pthread_mutex_unlock(&m_queNotifyMutex);
    pthread_cond_signal(&m_queNotifyCond);
}

void CEsfDispatcher::PushAuthEvent(ESFEvent *message)
{
    if (!message || !message->message)
    {
        return;
    }
    
    LOG_INFO("Push auth event");
    pthread_mutex_lock(&m_queAuthMutex);

    // 检查队列大小限制，防止内存无限增长
    if (m_queAuthEvent.size() >= AUTHEVENT_QUESIZE)
    {
        // 丢弃最老的事件
        ESFEvent *oldEvent = m_queAuthEvent.front();
        m_queAuthEvent.pop();
        es_release_message(oldEvent->message);
        free(oldEvent);
    }

    m_queAuthEvent.push(message);
    pthread_mutex_unlock(&m_queAuthMutex);
    pthread_cond_signal(&m_queAuthCond);
}

void CEsfDispatcher::SubscribeEvent(es_event_type_t eventType, IESFEventObserver *observer)
{
    LOG_DEBUG("Subscribing to event type: {}", static_cast<int>(eventType));
    if ( !observer )
    {
        LOG_ERROR("Subscribe event failed: observer is null, event_type={}", static_cast<int>(eventType));
        return;
    }

    auto &vec = m_eventSubscriptions[eventType];
    if ( std::find(vec.begin(), vec.end(), observer) != vec.end() )
    {
        LOG_WARN("Event {} already subscribed by this observer", static_cast<int>(eventType));
        return;
    }

    vec.push_back(observer);
}

//事件处理回调
void CEsfDispatcher::handleNotifyEvent(es_client_t *client, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in notify handler");
        return;
    }
    CEsfDispatcher *dispatcher = CEsfDispatcher::shared();
    if ( dispatcher )
    {
        // Notify事件：仅记录，不拦截
        dispatcher->dispatchNotifyEvent(message->event_type, message);
    }
}

void CEsfDispatcher::handleAuthEvent(es_client_t *client, const es_message_t *message)
{
    LOG_INFO("Processing auth event: {}", static_cast<int>(message->event_type));
    if ( !message )
    {
        LOG_ERROR("Received null message in auth handler");
        return;
    }

    CEsfDispatcher *dispatcher  = CEsfDispatcher::shared();
    bool            shouldAllow = true;
    if ( dispatcher )
    {
        shouldAllow = dispatcher->dispatchAuthEvent(message->event_type, message);
    }

    es_auth_result_t    authResult = shouldAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY;
    es_respond_result_t result     = ES_RESPOND_RESULT_SUCCESS;

    // 根据不同事件类型使用不同的响应方式
    switch (message->event_type)
    {
            
        case ES_EVENT_TYPE_AUTH_EXEC:
            // exec 事件使用 auth_result
            LOG_INFO("EXEC");
            result = es_respond_auth_result(client, message, authResult, false);
            break;
            
        case ES_EVENT_TYPE_AUTH_CREATE:
            // create 事件使用 auth_result
            LOG_INFO("CREATE");
            result = es_respond_auth_result(client, message, authResult, false);
            break;
            
        case ES_EVENT_TYPE_AUTH_RENAME:
            // rename 事件使用 auth_result
            LOG_INFO("RENAME");
            result = es_respond_auth_result(client, message, authResult, false);
            break;
            
        default:
            LOG_WARN("Unhandled auth event type: {}", static_cast<int>(message->event_type));
            // 其他 auth 事件默认使用 auth_result
            result = es_respond_auth_result(client, message, authResult, false);
            break;
    }

    if ( result != ES_RESPOND_RESULT_SUCCESS )
    {
        LOG_ERROR("es_respond_xxx failed for event {} with result {} authResult {}",
                  static_cast<int>(message->event_type), static_cast<int>(result), (authResult == ES_AUTH_RESULT_ALLOW ? "ALLOW" : "DENY"));
        
        // 如果响应失败，尝试使用默认的允许响应
        if ( result == ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT )
        {
            LOG_WARN("Invalid argument, using default allow policy");
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        }
    }
}

//派发事件
bool CEsfDispatcher::dispatchAuthEvent(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in auth dispatcher, event_type={}, defaulting to allow", static_cast<int>(eventType));
        return true;  // 默认放行
    }
    
    std::lock_guard<std::mutex> lock(m_subscriptionMutex);
    auto                        it = m_eventSubscriptions.find(eventType);
    if ( it != m_eventSubscriptions.end() )
    {
        const auto &observers = it->second;
        for ( auto *observer: observers )
        {
            if ( observer )
            {
                try
                {
                    // Auth事件：需要决策，如果返回false则拒绝
                    if ( !observer->OnAuthEventReceived(eventType, message) )
                    {
                        LOG_INFO("Auth event denied by observer, event_type={}, observer={}", static_cast<int>(eventType), static_cast<void*>(observer));
                        return false;  // 拒绝
                    }
                }
                catch ( const std::exception &e )
                {
                    LOG_ERROR("Exception in auth event observer: {}, event_type={}, observer={}", e.what(), static_cast<int>(eventType), static_cast<void*>(observer));
                }
                catch ( ... )
                {
                    LOG_ERROR("Unknown exception in auth event observer, event_type={}, observer={}", static_cast<int>(eventType), static_cast<void*>(observer));
                }
            }
        }
    }
    return true;  // 默认放行
}

void CEsfDispatcher::dispatchNotifyEvent(es_event_type_t eventType, const es_message_t *message)
{
    if ( !message )
    {
        LOG_ERROR("Received null message in notify dispatcher, event_type={}", static_cast<int>(eventType));
        return;
    }
    std::lock_guard<std::mutex> lock(m_subscriptionMutex);
    auto                        it = m_eventSubscriptions.find(eventType);
    if ( it != m_eventSubscriptions.end() )
    {
        const auto &observers = it->second;
        for ( auto *observer: observers )
        {
            if ( observer )
            {
                try
                {
                    observer->OnNotifyEventReceived(eventType, message);
                }
                catch ( const std::exception &e )
                {
                    LOG_ERROR("Exception in notify event observer: {}, event_type={}, observer={}", e.what(), static_cast<int>(eventType), static_cast<void*>(observer));
                }
                catch ( ... )
                {
                    LOG_ERROR("Unknown exception in notify event observer, event_type={}, observer={}", static_cast<int>(eventType), static_cast<void*>(observer));
                }
            }
        }
    }
}


//派发线程函数
void* CEsfDispatcher::dispatchNotifyThreadFunc(void *arg)
{
    LOG_INFO("DispatchNotifyThread started");
    CEsfDispatcher *self = static_cast<CEsfDispatcher *>(arg);

    while ( true )
    {
        pthread_mutex_lock(&self->m_queNotifyMutex);

        // 等待队列非空
        while ( self->m_queNotifyEvent.empty() )
        {
            pthread_cond_wait(&self->m_queNotifyCond, &self->m_queNotifyMutex);
        }

        // 出队
        ESFEvent *event = self->m_queNotifyEvent.front();
        self->m_queNotifyEvent.pop();

        pthread_mutex_unlock(&self->m_queNotifyMutex);

        self->handleNotifyEvent(event->client, event->message);
        m_notifyEventsProcessed.fetch_add(1);

        es_release_message(event->message);
        free(event);
    }

    return nullptr;
}

void* CEsfDispatcher::authWorkerThreadFunc(void *arg)
{
    pthread_t tid = pthread_self();
    LOG_INFO("Auth worker thread started, tid={}", (void*)tid);
    CEsfDispatcher *self = static_cast<CEsfDispatcher *>(arg);

    while (true)
    {
        pthread_mutex_lock(&m_queAuthMutex);

        // 等待队列非空，单个事件立即处理
        while (m_queAuthEvent.empty())
        {
            pthread_cond_wait(&m_queAuthCond, &m_queAuthMutex);
        }

        // 立即取出一个事件处理，无批量等待
        ESFEvent *event = m_queAuthEvent.front();
        m_queAuthEvent.pop();
        size_t queueSize = m_queAuthEvent.size();
        pthread_mutex_unlock(&m_queAuthMutex);

        if (queueSize > NOTIFYEVENT_QUESIZE)
        {
            LOG_DEBUG("Auth queue size high: {}, worker_tid={}", queueSize, (void*)tid);
        }

        // 立即处理事件，减少响应延迟
        try
        {
            handleAuthEvent(event->client, event->message);
            m_authEventsProcessed.fetch_add(1);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Exception in auth worker thread: {}, tid={}", e.what(), (void*)tid);
        }
        catch (...)
        {
            LOG_ERROR("Unknown exception in auth worker thread, tid={}", (void*)tid);
        }

        es_release_message(event->message);
        free(event);
    }

    LOG_INFO("Auth worker thread terminated, tid={}", (void*)tid);
    return nullptr;
}

CEsfDispatcher::CEsfDispatcher()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // 创建Notify单线程
    int threadNotify = pthread_create(&m_dispatchNotifyThread, &attr, CEsfDispatcher::dispatchNotifyThreadFunc, (void *)this);
    if (threadNotify != 0)
    {
        LOG_ERROR("Failed to create notify thread, result={}", threadNotify);
        pthread_attr_destroy(&attr);
    }
    LOG_INFO("Notify worker thread created successfully");
    
    
    m_authThreadPool.reserve(kAuthThreadPoolSize);
    for (size_t i = 0; i < kAuthThreadPoolSize; ++i)
    {
        pthread_t authThread;
        int result = pthread_create(&authThread, &attr, CEsfDispatcher::authWorkerThreadFunc, (void *)this);
        if (result != 0) {
            LOG_ERROR("Failed to create auth worker thread {}, error={}", i, result);
            pthread_attr_destroy(&attr);
        }
        m_authThreadPool.push_back(authThread);
    }
    pthread_attr_destroy(&attr);
    LOG_INFO("All dispatch threads created successfully - notify: 1, auth pool: {}", kAuthThreadPoolSize);
}

CEsfDispatcher::~CEsfDispatcher()
{
    
}
