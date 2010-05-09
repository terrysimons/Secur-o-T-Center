#ifndef __DETECTION_EVENT_H__
#define __DETECTION_EVENT_H__

#include <windows.h>
#include <list>
#include "productinfo.h"

using namespace std;

// Product Events:
// AV - AntiVirus
// AS - AntiSpyware
// FW - Firewall

typedef enum WHISKER_EVENT_REGISTRATION_TYPE {
	EVENT_REGISTRATION_TYPE_NONE      = 0,
	EVENT_REGISTRATION_TYPE_AV        = 2,
	EVENT_REGISTRATION_TYPE_AS        = 4,
	EVENT_REGISTRATION_TYPE_FW        = 8,
	EVENT_REGISTRATION_TYPE_RAW       = 16,
	EVENT_REGISTRATION_TYPE_PROCESSED = 32,
	EVENT_REGISTRATION_TYPE_ALL       = EVENT_REGISTRATION_TYPE_AV  | \
									    EVENT_REGISTRATION_TYPE_AS  | \
								        EVENT_REGISTRATION_TYPE_FW  | \
										EVENT_REGISTRATION_TYPE_RAW | \
										EVENT_REGISTRATION_TYPE_PROCESSED
}WHISKER_EVENT_REGISTRATION_TYPE;

typedef enum WHISKER_EVENT_DETECTION_TYPE {
	EVENT_TYPE_WSC,
	EVENT_TYPE_MSFW,
	EVENT_TYPE_MSDEFENDER
}WHISKER_EVENT_DETECTION_TYPE;

typedef enum WHISKER_EVENT_TYPE {
	PRODUCT_RAW_EVENT,
	PRODUCT_INSTALL_EVENT,
	PRODUCT_UNINSTALL_EVENT,
	PRODUCT_REALTIME_ENABLE_EVENT,
	PRODUCT_REALTIME_DISABLE_EVENT,
	PRODUCT_DEFINITIONS_UP_TO_DATE_EVENT,
	PRODUCT_DEFINITIONS_OUT_OF_DATE_EVENT,
	//PRODUCT_VERSION_CHANGED_EVENT,
	//PRODUCT_DEFINITION_VERSION_CHANGED_EVENT
}WHISKER_EVENT_TYPE;

struct productChangedEvent {
	WHISKER_EVENT_TYPE eventType;
	struct productInfo productInfo;
};

HRESULT RegisterProductStateChanges(void (*productStateChangeCallback)(list<struct productChangedEvent> &productList), 
									int registrationType);

void WINAPI ProductStateChangeOccurred(void *param);

HRESULT UnregisterProductStateChanges();

HRESULT DetectAntiVirusProducts(list<struct productInfo> *avList);
HRESULT DetectAntiSpywareProducts(list<struct productInfo> *asList);
HRESULT DetectFirewallProducts(list<struct productInfo> *fwList);

#endif // __DETECTION_EVENT_H__