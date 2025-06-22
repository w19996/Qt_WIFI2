#pragma once

#include <QWidget>
#include <QMainWindow>
#include "wifi.h"
QT_BEGIN_NAMESPACE
namespace Ui {
    class Widget;
}
QT_END_NAMESPACE

class Widget : public QMainWindow
{
    Q_OBJECT

public:
    Widget(QWidget* parent = nullptr);
    wifi* wf;
    ~Widget();
public slots:
	void onDataReady(QString ssid, QString path, QString password);
    void saveFile();
private:
    Ui::Widget* ui;
};

