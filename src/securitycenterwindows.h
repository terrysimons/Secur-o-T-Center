#ifndef __SECURITY_CENTER_WINDOWS_H__
#define __SECURITY_CENTER_WINDOWS_H__

#include "securitycenter.h"

void *RegisterSystemHealthNotifications(SecurityCenter *securityCenter);
void UnregisterSystemHealthNotifications(void *registrationHandle);

#endif // __SECURITY_CENTER_WINDOWS_H__