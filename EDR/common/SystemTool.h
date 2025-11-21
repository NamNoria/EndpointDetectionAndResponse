#ifndef SYSTEMTOOL_H
#define SYSTEMTOOL_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>
#include <string>

time_t GetUtcTime(const es_message_t *msg);
pid_t GetPid(const es_message_t *msg);
pid_t GetPPid(const es_message_t *msg);
pid_t GetPPid(pid_t pid);
NSString *GetProcessPath(const es_message_t *msg);
std::string GetProcessPath(pid_t pid);
NSString *GetSHA256(const es_message_t *msg);
NSString *GetSHA256(pid_t pid);
NSString *GetUser(const es_message_t *msg);
NSString *GetUser(pid_t pid);
uid_t GetUid(const es_message_t *msg);
uid_t GetUid(pid_t pid);
NSString *GetCMD(const es_message_t *msg);
NSString *GetCMD(pid_t pid);
NSString *GetPWD(const es_message_t *msg);
NSString *GetPWD(pid_t pid);
NSString *GetGUID(const es_message_t *msg);
std::string GetGUID(pid_t pid);
std::string GetSignerName(const std::string &path);
time_t GetCreateTime(const es_message_t *msg);
time_t GetCreateTime(pid_t pid);
size_t GetFileSize(pid_t pid);
int GetSignStatus(const std::string &path);
#endif  // SYSTEMTOOL_H

