#include "widget.h"
#include "ui_widget.h"
#include "AlgoInfo.h"
#include "drv_user.h"
#include <QMainWindow>
#include <QMenuBar>
#include <QMenu>
#include <QAction>

Widget::Widget(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::Widget)
{
	QWidget* central = new QWidget(this);  // 创建一个 QWidget 用作中心窗口
	ui->setupUi(central);  
	this->resize(800, 600); // 初始大小为 800x600，用户仍可拉伸
	setCentralWidget(central);

	QMenu* fileMenu = menuBar()->addMenu("文件");
    QAction* saveAction = fileMenu->addAction("保存");

	//fileMenu->addAction("保存", this, []() { qDebug() << "保存"; });
	fileMenu->addAction("退出", this, SLOT(close()));

    ui->tableWidget->setColumnCount(3);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "SSID" << "配置路径" << "密码");
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    //ui->tableWidget->setRowCount(1);

    Algo algo(AlgorithmInfo);
    wf = new wifi;
    connect(wf, &wifi::add_table, this, &Widget::onDataReady);
    connect(saveAction, &QAction::triggered, this, &Widget::saveFile);

	Drv b;
	b.GetOSPath();
    for (const auto& drive : b.m_drives)
    {
        constant::root_dump = drive.absoluteFilePath().toStdString();//设置系统盘符
        User c;
		c.GetUser(constant::root_dump);//设置用户名
        for (const auto& user : c.m_userList)
        {
            constant::username = user.toStdString();
			wf->run("wifi");
			wf->doWork();
        }
		
    }

}


void Widget::onDataReady(QString ssid, QString path, QString password)
{
	int row = ui->tableWidget->rowCount();
	ui->tableWidget->insertRow(row);
	ui->tableWidget->setItem(row, 0, new QTableWidgetItem(ssid));
	ui->tableWidget->setItem(row, 1, new QTableWidgetItem(path));
	ui->tableWidget->setItem(row, 2, new QTableWidgetItem(password));
}


void Widget::saveFile()
{
	QString filename = QFileDialog::getSaveFileName(this, "保存文件", "", "文本文件 (*.txt)");
	if (filename.isEmpty())
		return;

	QFile file(filename);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
		QMessageBox::warning(this, "错误", "无法打开文件进行写入");
		return;
	}

	QTextStream out(&file);
	for (const auto& info : this->wf->pwdFound)
	{
		out << "SSID：" << info["SSID"] << "\t" << "xmlPath：" << info["xmlPath"] << "\t" << "password：" << info["password"] << "\n";
	}

	file.close();
	QMessageBox::information(this, "成功", "保存成功！");
    
}

Widget::~Widget()
{
    delete ui;
}
