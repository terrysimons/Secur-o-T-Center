#include "eventdetection.h"
#include <windows.h>
#include <stdio.h>

bool productCheckNeeded = true;

void WINAPI ProductStateChangeOccurred(void *param) {
	EVENT_DETECTION_TYPE eventType = (EVENT_DETECTION_TYPE)(int)param;
	char eventTypeName[32]         = {0};

	//printf("\nProduct Change Event Posted!\n");

	switch(eventType) {
		case EVENT_TYPE_WSC:
			strncpy_s(eventTypeName, "WSC", sizeof(eventTypeName) - 1);
			break;
		case EVENT_TYPE_MSFW:
			strncpy_s(eventTypeName, "MS Firewall", sizeof(eventTypeName) - 1);
			break;
		case EVENT_TYPE_MSDEFENDER:
			strncpy_s(eventTypeName, "MS Defender", sizeof(eventTypeName) - 1);
			break;
		default: 
			strncpy_s(eventTypeName, "Unknown Product", sizeof(eventTypeName) - 1);
	};

	printf("%s triggered a product change event.\n", eventTypeName);

	productCheckNeeded = true;
}
