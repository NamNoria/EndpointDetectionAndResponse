#include "CThreatDetect.h"
#include "common/Logger.h"
#include "module/CProcessTree.h"
#include "ESF/CEsfClientManager.h"
#include "ESF/CEsfDispatcher.h"
#include "IESFEventObserver.h"
#include "CProcessThreatDetect.h"
#include "CFileThreatDetect.h"
#include "CNetThreatDetect.h"
#include "CInstallerDetect.h"
#include "macro.h"

uint64_t gSilentStartUtc = static_cast<uint64_t>(time(nullptr));

class CThreatDetect::Impl
{
public:
    Impl()
    {
        pthread_mutex_init(&m_switchMutex, nullptr);
        m_bInitialized = Initialize();
    }

    ~Impl()
    {
        UnInitialize();
        pthread_mutex_destroy(&m_switchMutex);
    }

    bool Initialize()
    {
        try
        {
            Logger::instance().init();
            LOG_INFO("\n===============================================\n=== EDR threat detection system starting... ===\n===============================================\n");

            m_pProcessTree = CProcessTree::shared();
            if (m_pProcessTree)
            {
                m_pProcessTree->StartAging();
            }
            
            m_pEsfClientManager = CEsfClientManager::shared();
            m_pEsfDispatcher = CEsfDispatcher::shared();
            
            m_pProcessThreatDetect = CProcessThreatDetect::shared();
            m_pFileThreatDetect = CFileThreatDetect::shared();
            m_pNetThreatDetect = CNetThreatDetect::shared();
            m_pInstallerDetect = CInstallerDetect::shared();
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Exception during initialization: {}", e.what());
            return false;
        }
        catch (...)
        {
            LOG_ERROR("Unknown exception during initialization");
            return false;
        }

        m_observers.push_back(m_pProcessThreatDetect);
        m_observers.push_back(m_pFileThreatDetect);
        m_observers.push_back(m_pInstallerDetect);
        return true;
    }

    void UnInitialize()
    {
        try
        {
            LOG_INFO("=== EDR threat detection system shutting down... ===");

            // 目前只有进程树需要清理，其他组件尚未启用
            // CProcessTree 的清理由其析构函数自动完成

            m_bInitialized = false;
            LOG_INFO("EDR shutdown complete");
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Exception during UnInitialize: {}", e.what());
        }
        catch (...)
        {
            LOG_ERROR("Unknown exception during UnInitialize");
        }
    }

    void SetSwitch(uint32_t iSwitch)
    {
        // 设置每个功能订阅信息
        
        // 统一设置调用，以此控制是否订阅事件
        for (auto observer : m_observers)
        {
            if (!observer)
            {
                LOG_WARN("Observer is nullptr for enable operation");
                continue;
            }
            
            for (auto eventtype : observer->GetSubscribedEventTypes())
            {
                m_pEsfDispatcher->SubscribeEvent(eventtype, observer);
            }
        }
        
        m_pEsfClientManager->setNotifySubscription();
        m_pEsfClientManager->setAuthSubscription();
    }
public:
    CProcessTree *m_pProcessTree = nullptr;
    CEsfClientManager *m_pEsfClientManager = nullptr;
    CEsfDispatcher *m_pEsfDispatcher = nullptr;
    CProcessThreatDetect *m_pProcessThreatDetect = nullptr;
    CFileThreatDetect *m_pFileThreatDetect = nullptr;
    CNetThreatDetect *m_pNetThreatDetect = nullptr;
    CInstallerDetect *m_pInstallerDetect = nullptr;
    std::vector<IESFEventObserver *> m_observers;
    
    bool m_bInitialized = false;
    
    uint32_t m_iSwitch = 0;
    pthread_mutex_t m_switchMutex;
//
//    bool m_bAuthInitizlized = false;
//    pthread_mutex_t m_authMutex;
//
//    pthread_t m_reportThread;
//    pthread_t m_FetchSwitchThread;
//    pthread_t m_FetchRuleThread;
//
//    pthread_mutex_t m_queMutex;
//    pthread_cond_t m_queCond;
//    std::queue<CThreatEvent*> m_queEvents;
};

CThreatDetect* CThreatDetect::Shared()
{
    static CThreatDetect instance;
    return &instance;
}

bool CThreatDetect::SetSwitch(uint32_t iSwitch)
{
    if (!m_pImpl)
    {
        return false;
    }

    if ((iSwitch & ~EDR_FEATURE_ALL) != 0)
    {
        return false;
    }

    if (iSwitch == m_pImpl->m_iSwitch)
    {
        LOG_INFO("EDR switch already set to: 0x{:08X} [ProcessStart:{} ProcessTree:{} FileCreate:{} FileRename:{} NetworkMonitor:{}]",
                 iSwitch,
                 (iSwitch & EDR_FEATURE_PROCESS_START) ? "ON" : "OFF",
                 (iSwitch & EDR_FEATURE_PROCESS_TREE) ? "ON" : "OFF",
                 (iSwitch & EDR_FEATURE_FILE_CREATE) ? "ON" : "OFF",
                 (iSwitch & EDR_FEATURE_FILE_RENAME) ? "ON" : "OFF",
                 (iSwitch & EDR_FEATURE_NETWORK_MONITOR) ? "ON" : "OFF");
        return true;
    }

    uint32_t oldSwitch = m_pImpl->m_iSwitch;

    pthread_mutex_lock(&m_pImpl->m_switchMutex);
    m_pImpl->m_iSwitch = iSwitch;
    pthread_mutex_unlock(&m_pImpl->m_switchMutex);

    m_pImpl->SetSwitch(iSwitch);
    LOG_INFO("EDR switch changed: 0x{:08X} -> 0x{:08X} [ProcessStart:{} ProcessTree:{} FileCreate:{} FileRename:{} NetworkMonitor:{}]",
             oldSwitch, iSwitch,
             (iSwitch & EDR_FEATURE_PROCESS_START) ? "ON" : "OFF",
             (iSwitch & EDR_FEATURE_PROCESS_TREE) ? "ON" : "OFF",
             (iSwitch & EDR_FEATURE_FILE_CREATE) ? "ON" : "OFF",
             (iSwitch & EDR_FEATURE_FILE_RENAME) ? "ON" : "OFF",
             (iSwitch & EDR_FEATURE_NETWORK_MONITOR) ? "ON" : "OFF");
    return true;
}

uint32_t CThreatDetect::GetSwitch()
{
    if (!m_pImpl)
    {
        return 0;
    }

    pthread_mutex_lock(&m_pImpl->m_switchMutex);
    uint32_t result = m_pImpl->m_iSwitch;
    pthread_mutex_unlock(&m_pImpl->m_switchMutex);

    return result;
}

CThreatDetect::CThreatDetect()
{
    try
    {
        m_pImpl = std::make_unique<Impl>();
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Exception during construction: {}", e.what());
        m_pImpl.reset();
    }
    catch (...)
    {
        LOG_ERROR("Unknown exception during construction");
        m_pImpl.reset();
    }
}
CThreatDetect::~CThreatDetect()
{
    
}
