#ifndef __DETECTION_EVENT_H__
#define __DETECTION_EVENT_H__

#include <windows.h>

extern bool productCheckNeeded;

// Product Events:
// AV - AntiVirus
// AS - AntiSpyware
// FW - Firewall

typedef enum WISKER_EVENT_REGISTRATION_TYPE {
	EVENT_REGISTRATION_TYPE_NONE   = 0,
	EVENT_REGISTRATION_TYPE_AV     = 2,
	EVENT_REGISTRATION_TYPE_AS     = 4,
	EVENT_REGISTRATION_TYPE_FW     = 8,
	EVENT_REGISTRATION_TYPE_FILTER = 16,
	EVENT_REGISTRATION_TYPE_ALL    = EVENT_REGISTRATION_TYPE_AV | \
									 EVENT_REGISTRATION_TYPE_AS | \
								     EVENT_REGISTRATION_TYPE_FW
}WISKER_EVENT_REGISTRATION_TYPE;

typedef enum WISKER_EVENT_DETECTION_TYPE {
	EVENT_TYPE_WSC,
	EVENT_TYPE_MSFW,
	EVENT_TYPE_MSDEFENDER
}WISKER_EVENT_DETECTION_TYPE;

HRESULT RegisterProductStateChanges(LPTHREAD_START_ROUTINE productStateChangeCallback, 
									int registrationType);

void WINAPI ProductStateChangeOccurred(void *param);

HRESULT UnregisterProductStateChanges();

HRESULT DetectAntiVirusProducts();
HRESULT DetectAntiSpywareProducts();
HRESULT DetectFirewallProducts();

#endif // __DETECTION_EVENT_H__