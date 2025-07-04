#pragma once

#include <QtGlobal>
#include <windows.h>
class Logger
{
public:
    static void initialize(bool logToConsole = true);
    static void setMinimumLevel(QtMsgType level); // 设置最低记录级别

    static QString winError(DWORD errCode = GetLastError());
private:
    static void messageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg);
    static QtMsgType minLevel;
    static bool logToConsole;
    static QString logFilePath;
    static QString date;
};



