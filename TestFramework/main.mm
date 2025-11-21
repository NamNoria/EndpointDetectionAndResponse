#import <Cocoa/Cocoa.h>
#include "CThreatDetect.h"
#import <GetHardwareInfo/HardwareInfo.h>
#include <string>

//void cleanup() { NSLog(@"atexit cleanup called"); }

int main(int argc, const char *argv[])
{
    @autoreleasepool
    {
        
        // 先获取并打印一次硬件信息
//        HardwareInfo hw;
//        std::string hwInfo = hw.GetHardwareInfo(nullptr);
//        NSLog(@"Hardware Info:\n%.*s", (int)hwInfo.size(), hwInfo.c_str());
         
        
        CThreatDetect *detector = CThreatDetect::Shared();
        if (detector)
        {
            detector->SetSwitch(EDR_FEATURE_ALL);
        }
        else
        {
            NSLog(@"CThreatDetect initialization failed");
        }
        [[NSRunLoop mainRunLoop] run];
    }
    
    return 0;
}
