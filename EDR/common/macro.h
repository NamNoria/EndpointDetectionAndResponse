#ifndef MACRO_H
#define MACRO_H

#pragma mark  -Length
#define USER_LENGTH         32
#define SIGNERNAME_LENGTH   128
#define SHA256_LENGTH       65
#define COMMANDLINE_LENGTH  4096
#define PROCESS_LENGTH_1024 1024
#define PROCESS_LENGTH_4096 4096

#define EVENT_QUEUE_SIZE   0x1000
#pragma mark -YunShuCommon
#define kYunshuConfigUserInfoPath               @"/opt/.yunshu/config/agent_config"

#pragma mark -QUESIZE
#define AUTHEVENT_QUESIZE 500
#define NOTIFYEVENT_QUESIZE 500
#endif // !MACRO_H
