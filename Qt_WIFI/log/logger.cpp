#include "logger.h"
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QDir>
#include <QMutex>
#include <QMutexLocker>
#include <QThread>
#include <QCoreApplication>
#include <iostream>

static QMutex logMutex;
QtMsgType Logger::minLevel = QtDebugMsg;
bool Logger::logToConsole = true;
QString Logger::date = QDate::currentDate().toString("yyyy-MM-dd");
QString Logger::logFilePath = "";
void Logger::initialize(bool toConsole)
{
    logToConsole = toConsole;
    logFilePath = QCoreApplication::applicationDirPath() + "/logs/log_" + date + ".txt";
    // 创建 logs 目录
    QDir dir(QCoreApplication::applicationDirPath() + "/logs");
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    //qDebug()<<QCoreApplication::applicationDirPath();
    QFile logFile(logFilePath);
    if (logFile.exists()) {
        logFile.remove();  // 删除旧文件（等价于清空）
    }
    logFile.close();

    qInstallMessageHandler(Logger::messageHandler);
}

void Logger::setMinimumLevel(QtMsgType level)
{
    minLevel = level;
}

void Logger::messageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg)
{
    if (type < minLevel)
        return;

    QMutexLocker locker(&logMutex);

    QString timeStamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");

    QString typeStr;

    switch (type) {
    case QtDebugMsg:    typeStr = "Debug"; break;
    case QtInfoMsg:     typeStr = "Info"; break;
    case QtWarningMsg:  typeStr = "Warning"; break;
    case QtCriticalMsg: typeStr = "Critical"; break;
    case QtFatalMsg:    typeStr = "Fatal"; break;
    }

    QString threadId = QString::number(reinterpret_cast<quintptr>(QThread::currentThreadId()), 16);

    QString logLine = QString("[%1] [%2] \t[Thread %3] \t[%4:%5] \t[%6]\n")
        .arg(timeStamp, -19)                    // 时间字段 19 宽度左对齐
        .arg(typeStr, -8)                       // 类型字段 8 宽度左对齐
        .arg(threadId, -10)                     // 线程 ID 左对齐
        .arg(QString(context.file ? context.file : ""), -20)  // 文件名左对齐
        .arg(context.line)
        .arg(msg);



    // 写入文件

    //qDebug()<<logFilePath<<"\n";
    QFile file(logFilePath);
    if (file.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&file);
        out << logLine;
        file.close();
    }

    // 可选控制台输出
    if (logToConsole) {
        std::cerr << logLine.toStdString();
    }

    if (type == QtFatalMsg) {
        abort();
    }
}

QString Logger::winError(DWORD errCode)
{
    LPWSTR buffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errCode, 0,
        (LPWSTR)&buffer, 0, nullptr);

    QString msg;
    if (size && buffer) {
        msg = QString::fromWCharArray(buffer).trimmed();
        LocalFree(buffer);
    }
    else {
        msg = QString("Unknown error code: %1").arg(errCode);
    }
    return msg;
}


