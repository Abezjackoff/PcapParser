#ifndef LOGGING_H
#define LOGGING_H

#include <string>
#include <iostream>

enum class LogLevel
{
    INFO,
    WARNING,
    ERROR
};

inline void console_log(const std::string& line, LogLevel lvl)
{
    std::string lvlPrefix;
    if (lvl == LogLevel::ERROR)         lvlPrefix = "[ERROR] ";
    else if (lvl == LogLevel::WARNING)  lvlPrefix = "[WARNING] ";
    else                                lvlPrefix = "[INFO] ";

    std::cout << lvlPrefix << line << "\n";
};

inline void console_log(const std::string& line)
{
    std::cout << line << "\n";
}

inline void console_log()
{
    std::cout << "\n";
};

#endif
