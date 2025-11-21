#include <EndpointSecurity/EndpointSecurity.h>
#include <set>
#include "CEsfClientManager.h"
#include "../common/Logger.h"
#include "CEsfDispatcher.h"


CEsfClientManager* CEsfClientManager::shared()
{
    static CEsfClientManager instance;
    return &instance;
}

CEsfClientManager::CEsfClientManager()
{
    try
    {
        m_pEsfDispatcher = CEsfDispatcher::shared();

        // 初始化Notify客户端
        if ( !initializeNotifyClient() )
        {
            LOG_ERROR("Failed to initialize notify client in Initialize()");
            return;
        }
        else
        {
            LOG_INFO("Succeed to initialize notify client");
        }

        // 初始化Auth客户端
        if ( !initializeAuthClient() )
        {
            LOG_ERROR("Failed to initialize auth client in Initialize()");
            return;
        }
        else
        {
            LOG_INFO("Succeed to initialize auth client");
        }

        // 设置Notify回调 - 仅记录，不拦截
        auto notifyHandler = ^(es_client_t *client, const es_message_t *message) {
            es_retain_message(message);

            ESFEvent *node = (ESFEvent *)malloc(sizeof(ESFEvent));

            node->client  = client;
            node->message = message;

            CEsfDispatcher::PushNotifyEvent(node);
        };
        setNotifyCallback(notifyHandler);

        auto authHandler = ^(es_client_t *client, const es_message_t *message) {
            es_retain_message(message);

            ESFEvent *node = (ESFEvent *)malloc(sizeof(ESFEvent));

            node->client  = client;
            node->message = message;

            CEsfDispatcher::PushAuthEvent(node);
        };
        setAuthCallback(authHandler);
        LOG_INFO("Client callbacks setup completed");
    }
    catch ( const std::exception &e )
    {
        LOG_ERROR("Exception during initialization: {}", e.what());
        return;
    }
    catch ( ... )
    {
        LOG_ERROR("Unknown exception during initialization");
        return;
    }
    return;
}

CEsfClientManager::~CEsfClientManager()
{
    
}

// 初始化客户端
bool CEsfClientManager::initializeNotifyClient()
{
    // 创建回调函数
    auto notifyHandler = ^(es_client_t *client, const es_message_t *message) {
        if ( m_notifyCallback )
        {
            m_notifyCallback(client, message);
        }
    };

    if ( __builtin_available(macOS 10.15, *) )
    {
        es_new_client_result_t result = es_new_client(&m_pNotifyClient, notifyHandler);
        if ( result != ES_NEW_CLIENT_RESULT_SUCCESS )
        {
            LOG_ERROR("Failed to create notify client, es_new_client result={}", static_cast<int>(result));
            return false;
        }
        return true;
    }
    else
    {
        return false;
    }
}

bool CEsfClientManager::initializeAuthClient()
{
    // 创建回调函数
    auto authHandler = ^(es_client_t *client, const es_message_t *message) {
        if ( m_authCallback )
        {
            m_authCallback(client, message);
        }
    };

    if ( __builtin_available(macOS 10.15, *) )
    {
        es_new_client_result_t result = es_new_client(&m_pAuthClient, authHandler);
        if ( result != ES_NEW_CLIENT_RESULT_SUCCESS )
        {
            LOG_ERROR("Failed to create auth client, es_new_client result={}", static_cast<int>(result));
            return false;
        }
        return true;
    }
    else
    {
        return false;
    }
}

bool CEsfClientManager::SetNotifySubscription()
{
    if ( !m_pNotifyClient || !m_pEsfDispatcher )
    {
        LOG_ERROR("setNotifySubscription failed: notify_client={}, dispatcher={}", static_cast<void*>(m_pNotifyClient), static_cast<void*>(m_pEsfDispatcher));
        return false;
    }

    // 获取所有观察者的订阅事件类型
    std::set<es_event_type_t> notifyEventTypes;
    for ( const auto &subscription: m_pEsfDispatcher->m_eventSubscriptions )
    {
        es_event_type_t eventType = subscription.first;
        switch ( eventType )
        {
            case ES_EVENT_TYPE_NOTIFY_EXIT:
            case ES_EVENT_TYPE_NOTIFY_CLOSE:
                notifyEventTypes.insert(eventType);
                break;
            default:
                break;
        }
    }

    // 订阅所有Notify事件
    if ( !notifyEventTypes.empty() )
    {
        std::vector<es_event_type_t> notifyEvents(notifyEventTypes.begin(), notifyEventTypes.end());
        es_return_t result = es_subscribe(m_pNotifyClient, notifyEvents.data(), (uint32_t)notifyEvents.size());
        if ( result != ES_RETURN_SUCCESS )
        {
            LOG_ERROR("Failed to subscribe notify events, es_subscribe result={}, event_count={}", static_cast<int>(result), notifyEvents.size());
            return false;
        }
        // 生成notify事件类型列表
        std::vector<std::string> notifyEventNames;
        for (auto eventType : notifyEvents)
        {
            std::string typeName;
            switch (eventType)
            {
                case ES_EVENT_TYPE_NOTIFY_EXIT:
                    typeName = "NOTIFY_EXIT";
                    break;
                case ES_EVENT_TYPE_NOTIFY_CLOSE:
                    typeName = "NOTIFY_CLOSE";
                    break;
                case ES_EVENT_TYPE_NOTIFY_FORK:
                    typeName = "NOTIFY_FORK";
                    break;
                case ES_EVENT_TYPE_NOTIFY_EXEC:
                    typeName = "NOTIFY_EXEC";
                    break;
                default: typeName = "NOTIFY_" + std::to_string(static_cast<int>(eventType)); break;
            }
            notifyEventNames.push_back(typeName);
        }

        std::string notifyEventsList;
        for (size_t i = 0; i < notifyEventNames.size(); ++i)
        {
            if (i > 0)
            {
                notifyEventsList += ", ";
            }
            notifyEventsList += notifyEventNames[i];
        }
        LOG_INFO("Subscribed to {} notify events: [{}]", notifyEvents.size(), notifyEventsList);
    }

    return true;
}

bool CEsfClientManager::SetAuthSubscription()
{
    if ( !m_pAuthClient || !m_pEsfDispatcher )
    {
        LOG_ERROR("setAuthSubscription failed: auth_client={}, dispatcher={}", static_cast<void*>(m_pAuthClient), static_cast<void*>(m_pEsfDispatcher));
        return false;
    }

    // 获取所有观察者的订阅事件类型
    std::set<es_event_type_t> authEventTypes;
    for ( const auto &subscription: m_pEsfDispatcher->m_eventSubscriptions )
    {
        es_event_type_t eventType = subscription.first;
        // 如果是 AUTH 类型事件，加入到集合
        switch ( eventType )
        {
//            case ES_EVENT_TYPE_AUTH_EXEC:
//            case ES_EVENT_TYPE_AUTH_CREATE:
//            case ES_EVENT_TYPE_AUTH_RENAME:
//                authEventTypes.insert(eventType);
//                break;
            default:
                break;
        }
    }

    // 订阅所有Auth事件
    if ( !authEventTypes.empty() )
    {
        std::vector<es_event_type_t> authEvents(authEventTypes.begin(), authEventTypes.end());
        es_return_t result = es_subscribe(m_pAuthClient, authEvents.data(), (uint32_t)authEvents.size());
        if ( result != ES_RETURN_SUCCESS )
        {
            LOG_ERROR("Failed to subscribe auth events: {}", static_cast<int>(result));
            return false;
        }
        // 生成auth事件类型列表
        std::vector<std::string> authEventNames;
        for (auto eventType : authEvents)
        {
            std::string typeName;
            switch (eventType)
            {
                case ES_EVENT_TYPE_AUTH_EXEC: typeName = "AUTH_EXEC"; break;
                case ES_EVENT_TYPE_AUTH_CREATE: typeName = "AUTH_CREATE"; break;
                case ES_EVENT_TYPE_AUTH_RENAME: typeName = "AUTH_RENAME"; break;
                case ES_EVENT_TYPE_AUTH_OPEN: typeName = "AUTH_OPEN"; break;
                default: typeName = "AUTH_" + std::to_string(static_cast<int>(eventType)); break;
            }
            authEventNames.push_back(typeName);
        }

        std::string authEventsList;
        for (size_t i = 0; i < authEventNames.size(); ++i)
        {
            if (i > 0) authEventsList += ", ";
            authEventsList += authEventNames[i];
        }
        LOG_INFO("Subscribed to {} auth events: [{}]", authEvents.size(), authEventsList);
    }

    return true;
}
void CEsfClientManager::setNotifyCallback(es_handler_block_t callback)
{
    m_notifyCallback = callback;
    LOG_INFO("Notify callback set");
}

void CEsfClientManager::setAuthCallback(es_handler_block_t callback)
{
    m_authCallback = callback;
    LOG_INFO("Auth callback set");
}

