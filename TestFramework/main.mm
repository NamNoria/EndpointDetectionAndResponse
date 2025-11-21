#import <Cocoa/Cocoa.h>
#include "CThreatDetect.h"
#include <string>

//void cleanup() { NSLog(@"atexit cleanup called"); }

int main(int argc, const char *argv[])
{
    @autoreleasepool
    {
        
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
