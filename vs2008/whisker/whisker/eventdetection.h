#ifndef __DETECTION_EVENT_H__
#define __DETECTION_EVENT_H__

#include <windows.h>

extern bool productCheckNeeded;

typedef enum EVENT_DETECTION_TYPE {
	EVENT_TYPE_WSC,
	EVENT_TYPE_MSFW,
	EVENT_TYPE_MSDEFENDER
}EVENT_DETECTION_TYPE;

void WINAPI ProductStateChangeOccurred(void *param);

#endif // __DETECTION_EVENT_H__