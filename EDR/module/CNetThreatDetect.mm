#include "CNetThreatDetect.h"


CNetThreatDetect *CNetThreatDetect::shared()
{
    static CNetThreatDetect instance;
    return &instance;
}
