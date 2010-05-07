#ifdef WIN32

#include "securitycenterwindows.h"
#include <windows.h>
#include <wscapi.h>
#include <stdio.h>
#include "securitycenter.h"

void WINAPI SystemHealthDidChange(SecurityCenter *securityCenter) {
	// TODO: Post updates.
}

void *RegisterSystemHealthNotifications(SecurityCenter *securityCenter) {
	HRESULT result = S_OK;
	HANDLE callbackRegistration = NULL;
	WSC_SECURITY_PROVIDER_HEALTH fwHealth     = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
	WSC_SECURITY_PROVIDER_HEALTH avHealth     = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
	WSC_SECURITY_PROVIDER_HEALTH asHealth     = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
	WSC_SECURITY_PROVIDER_HEALTH updateHealth = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;

	result = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_FIREWALL, &fwHealth);
	result = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS, &avHealth);
	result = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTISPYWARE, &asHealth);
	result = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS, &updateHealth);

	result = WscRegisterForChanges(NULL, &callbackRegistration, (LPTHREAD_START_ROUTINE)SystemHealthDidChange, securityCenter);

	return callbackRegistration;
}

void UnregisterSystemHealthNotifications(void *registrationHandle) {
	HRESULT result = S_OK;

	result = WscUnRegisterChanges(registrationHandle);
}

#endif // WIN32