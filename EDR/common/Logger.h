#ifndef LOGGER_H
#define LOGGER_H

#include <memory>
#include <string>
#include <iostream>

// ========== 日志库选择 ==========
// 通过修改这里来替换日志库
#define USE_SPDLOG 1
// #define USE_GLOG 1
// #define USE_CUSTOM_LOG 1

#if USE_SPDLOG
    #include "spdlog/spdlog.h"
    #include "spdlog/sinks/stdout_color_sinks.h"
    #include "spdlog/sinks/base_sink.h"
    #include <fstream>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

#if USE_SPDLOG
// macOS 兼容的文件系统工具函数
namespace
{
    bool file_exists(const std::string& path)
    {
        struct stat st;
        return stat(path.c_str(), &st) == 0;
    }

    size_t get_file_size(const std::string& path)
    {
        struct stat st;
        if (stat(path.c_str(), &st) != 0)
        {
            return 0;
        }
        return st.st_size;
    }

    std::string get_parent_path(const std::string& path)
    {
        size_t pos = path.find_last_of('/');
        if (pos == std::string::npos)
        {
            return ".";
        }
        if (pos == 0)
        {
            return "/";
        }
        return path.substr(0, pos);
    }

    bool create_directories(const std::string& path)
    {
        if (path.empty() || file_exists(path))
        {
            return true;
        }

        std::string parent = get_parent_path(path);
        if (!create_directories(parent))
        {
            return false;
        }

        return mkdir(path.c_str(), 0755) == 0;
    }
}

// 自定义滚动文件sink，实现EdrLog.txt -> EdrLog1.txt -> EdrLog2.txt...的命名规则
class CustomRotatingFileSink : public spdlog::sinks::base_sink<std::mutex>
{
public:
    CustomRotatingFileSink(const std::string& base_filename, size_t max_size)
        : base_filename_(base_filename), max_size_(max_size), current_size_(0)
    {

        // 提取基础文件名和扩展名
        size_t dot_pos = base_filename_.find_last_of('.');
        if (dot_pos != std::string::npos)
        {
            base_name_ = base_filename_.substr(0, dot_pos);
            extension_ = base_filename_.substr(dot_pos);
        }
        else
        {
            base_name_ = base_filename_;
            extension_ = ".txt";
        }

        // 找到下一个可用的文件
        current_filename_ = find_next_filename();

        // 打开文件
        file_.open(current_filename_, std::ios::app);
        if (file_.is_open())
        {
            // 获取当前文件大小
            file_.seekp(0, std::ios::end);
            current_size_ = file_.tellp();
        }
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        // 检查是否需要轮转
        if (current_size_ >= max_size_)
        {
            rotate_file();
        }

        // 写入日志
        spdlog::memory_buf_t formatted;
        base_sink<std::mutex>::formatter_->format(msg, formatted);

        if (file_.is_open())
        {
            file_.write(formatted.data(), formatted.size());
            file_.flush();
            current_size_ += formatted.size();
        }
    }

    void flush_() override
    {
        if (file_.is_open())
        {
            file_.flush();
        }
    }

private:
    std::string find_next_filename()
    {
        // 首先检查基础文件名是否存在且未超过大小限制
        if (file_exists(base_filename_))
        {
            auto file_size = get_file_size(base_filename_);
            if (file_size < max_size_)
            {
                return base_filename_; // EdrLog.txt
            }
        }
        else
        {
            return base_filename_; // EdrLog.txt 不存在，创建它
        }

        // 查找下一个可用的编号文件
        int index = 1;
        std::string candidate;
        while (true)
        {
            candidate = base_name_ + std::to_string(index) + extension_; // EdrLog1.txt, EdrLog2.txt...
            if (!file_exists(candidate))
            {
                return candidate;
            }

            auto file_size = get_file_size(candidate);
            if (file_size < max_size_)
            {
                return candidate;
            }

            index++;
        }
    }

    void rotate_file()
    {
        if (file_.is_open())
        {
            file_.close();
        }

        // 找到下一个文件名
        current_filename_ = find_next_filename();

        // 打开新文件
        file_.open(current_filename_, std::ios::app);
        if (file_.is_open())
        {
            file_.seekp(0, std::ios::end);
            current_size_ = file_.tellp();
        }
        else
        {
            current_size_ = 0;
        }
    }

    std::string base_filename_;
    std::string base_name_;
    std::string extension_;
    std::string current_filename_;
    size_t max_size_;
    size_t current_size_;
    std::ofstream file_;
};
#endif

class Logger
{
public:
    static Logger& instance()
    {
        static Logger inst;
        return inst;
    }

    void init(const std::string& logFile = "/opt/.yunshu/EDR/EdrLog.txt")
    {
    #if USE_SPDLOG
        try {
            // 提取日志目录路径
            std::string actualLogFile = logFile;
            std::string logDir = get_parent_path(logFile);

            // 尝试创建日志目录
            bool dirCreated = false;
            if (!file_exists(logDir))
            {
                // 尝试直接创建目录
                if (create_directories(logDir))
                {
                    dirCreated = true;
                }
                else
                {
                    // 创建失败，使用本地目录作为替代
                    logDir = "./logs";
                    actualLogFile = logDir + "/EdrLog.txt";
                    if (!create_directories(logDir))
                    {
                        // 本地目录也失败，使用当前目录
                        logDir = ".";
                        actualLogFile = "./EdrLog.txt";
                    }
                    dirCreated = true;
                }
            }
            else
            {
                dirCreated = true;
            }

            if (!dirCreated)
            {
                throw std::runtime_error("Failed to create log directory: " + logDir);
            }

            // 控制台 + 自定义滚动文件双输出
            std::vector<spdlog::sink_ptr> sinks;
            sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());

            // 使用自定义滚动文件sink
            sinks.push_back(std::make_shared<CustomRotatingFileSink>(actualLogFile, 10 * 1024 * 1024));

            logger_ = std::make_shared<spdlog::logger>("app_logger", sinks.begin(), sinks.end());
            logger_->set_level(spdlog::level::debug);
            logger_->flush_on(spdlog::level::info);
            logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%s:%#] %v");

            // 记录实际使用的日志路径
            logger_->info("Logger initialized, log files saved to: {}", logDir);
        }
        catch (const spdlog::spdlog_ex& ex)
        {
            printf("Logger init failed: %s\n", ex.what());
            throw; // 重新抛出异常，确保调用方知道初始化失败
        }
    #endif
    }

#if USE_SPDLOG
    std::shared_ptr<spdlog::logger> get() { return logger_; }
#endif

private:
    Logger() = default;
    ~Logger() = default;

#if USE_SPDLOG
    std::shared_ptr<spdlog::logger> logger_;
#endif
};

// ========== 宏定义 ==========
// 方便解耦，将来换库只需修改宏实现
#if USE_SPDLOG
    #define LOG_DEBUG(...) SPDLOG_LOGGER_DEBUG(Logger::instance().get(), __VA_ARGS__)
    #define LOG_INFO(...)  SPDLOG_LOGGER_INFO(Logger::instance().get(), __VA_ARGS__)
    #define LOG_WARN(...)  SPDLOG_LOGGER_WARN(Logger::instance().get(), __VA_ARGS__)
    #define LOG_ERROR(...) SPDLOG_LOGGER_ERROR(Logger::instance().get(), __VA_ARGS__)
#else
    #define LOG_DEBUG(...) do { } while(0)
    #define LOG_INFO(...)  do { } while(0)
    #define LOG_WARN(...)  do { } while(0)
    #define LOG_ERROR(...) do { } while(0)
#endif
#endif
