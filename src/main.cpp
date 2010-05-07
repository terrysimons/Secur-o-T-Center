#include "securitycenter.h"
#include "securitycenterwindows.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	SecurityCenter w;
	w.show();
	return a.exec();
}
