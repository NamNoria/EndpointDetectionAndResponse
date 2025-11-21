#include "CFilterRule.h"

CFilterRule* CFilterRule::shared()
{
    static CFilterRule instance;
    return &instance;
}

bool CFilterRule::IsConfigLoaded()
{
    return true;
}
ActionStatus CFilterRule::FileRenameFilterAllow(FILE_RENAME_INFO *pEventInfo, THREAT_PROC_INFO* pProcInfo, std::string *outThreatInfo) const
{
    return RULE_ACTION_PASS;
}

ActionStatus CFilterRule::FileCreateFilterAllow(FILE_CREATE_INFO *pEventInfo, THREAT_PROC_INFO* pProcInfo, std::string *outThreatInfo) const
{
    return RULE_ACTION_PASS;
}

ActionStatus CFilterRule::ProcessFilterAllow(THREAT_PROC_INFO *pEventInfo, THREAT_PROC_INFO *pParentInfo, std::string *outThreatInfo) const
{
    return RULE_ACTION_PASS;
}

CFilterRule::CFilterRule()
{
    
}

CFilterRule::~CFilterRule()
{
    
}
