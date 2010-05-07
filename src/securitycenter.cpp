#include "securitycenter.h"

#ifdef WIN32
#include "securitycenterwindows.h"
#endif 

SecurityCenter::SecurityCenter(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	// This call should be defined per-platform.
	registrationHandle = RegisterSystemHealthNotifications(this);
}

SecurityCenter::~SecurityCenter()
{
	UnregisterSystemHealthNotifications(registrationHandle);
}
