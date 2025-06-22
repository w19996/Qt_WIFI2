#include "drv_user.h"

void Drv::GetOSPath()
{
    QFileInfoList drives = QDir::drives();
	wchar_t systemDir[MAX_PATH];

	UINT result = GetSystemDirectory(systemDir, MAX_PATH);
    QString localPath = QString::fromWCharArray(systemDir);
    localPath = localPath.left(2);
    for (const QFileInfo& drive : drives)
    {
        QString path = drive.absoluteFilePath();
        //qDebug() << "Drive:" << drive.absoluteFilePath();
        if (!path.startsWith(localPath, Qt::CaseInsensitive))
        {
			QFile file(drive.absoluteFilePath() + "Windows/explorer.exe");
			if (file.exists())
			{
				this->m_drives.append(drive);
			}
        }
        
    }
    qDebug() << m_drives;
}
void User::GetUser(std::string rootPath)
{
    QDir dir(QString::fromStdString(rootPath + "Users"));
    if (!dir.exists())
        return;
    QFileInfoList entries = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
    //qDebug()<<entries;
    for (const QFileInfo& entry : entries)
    {
        QString name = entry.fileName();

        // 过滤默认用户
        if (name == "All Users" || name == "Default User" || name == "Default"
            || name == "Public" || name == "desktop.ini" || name == ".DS_Store")
            continue;
        m_userList << name;
    }
    //qDebug()<<m_userList[0];
}
