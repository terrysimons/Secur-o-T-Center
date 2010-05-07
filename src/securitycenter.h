#ifndef SECURITYCENTER_H
#define SECURITYCENTER_H

#include <QtGui/QMainWindow>
#include "ui_securitycenter.h"

class SecurityCenter : public QMainWindow
{
	Q_OBJECT

public:
	SecurityCenter(QWidget *parent = 0, Qt::WFlags flags = 0);
	~SecurityCenter();

private:
	Ui::SecurityCenterClass ui;
};

#endif // SECURITYCENTER_H
