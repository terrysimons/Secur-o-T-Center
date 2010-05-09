#include <iostream>
#include <list>
#include <process.h>
#include "windowsfw.h"
#include "eventdetection.h"
#include "productinfo.h"

using namespace std;

bool done = false;

list <struct productInfo> avList;
list <struct productInfo> asList;
list <struct productInfo> fwList;

BOOL WINAPI ConsoleHandler(DWORD CEvent) {

	printf("Got Control!\n");

	switch(CEvent) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
			printf("Done!");
			done = true;
			break;
		default:
			printf("Unhandled control event!\n");
	};

	return TRUE;
}

void EventNotificationCallback(list<struct productChangedEvent> &changedProducts) {
	list<struct productChangedEvent>::iterator currentEvent;

	currentEvent = changedProducts.begin();

	while(currentEvent != changedProducts.end()) {

		switch(currentEvent->eventType) {
			case PRODUCT_RAW_EVENT:
				// Throw away raw events.
				break;
			case PRODUCT_INSTALL_EVENT:
				printf("Product Install Event\n");
				break;
			case PRODUCT_UNINSTALL_EVENT:
				printf("Product Uninstall Event\n");
				break;
			case PRODUCT_REALTIME_ENABLE_EVENT:
				printf("Product Realtime Enable Event\n");
				break;
			case PRODUCT_REALTIME_DISABLE_EVENT:
				printf("Product Realtime Disable Event\n");
				break;
			case PRODUCT_DEFINITIONS_UP_TO_DATE_EVENT:
				printf("Product Definitions Are Current Event\n");
				break;
			case PRODUCT_DEFINITIONS_OUT_OF_DATE_EVENT:
				printf("Product Definitions Are Out of Date Event\n");
				break;
			default:
				printf("Unknown Event Type: %d\n", currentEvent->eventType);
		};

		currentEvent++;
	}
}

int main(int argc, char **argv) {
	HRESULT hres = S_OK;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x" 
            << hex << hres << endl;
        return hres;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------
    // Note: If you are using Windows 2000, you need to specify -
    // the default authentication credentials for a user by using
    // a SOLE_AUTHENTICATION_LIST structure in the pAuthList ----
    // parameter of CoInitializeSecurity ------------------------

    hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );

                      
    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x" 
            << hex << hres << endl;
        CoUninitialize();
        return hres;                    // Program has failed.
    }

	// So we can handle control-c to break.
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);

	// Register for all product event types, but filter events.
	// This will ensure that we only get notified of hard changes.
	// It prevents blipping that can occur during installation/removal of products.
	RegisterProductStateChanges(&EventNotificationCallback, 
								EVENT_REGISTRATION_TYPE_ALL);

	DetectAntiVirusProducts(&avList);
	DetectAntiSpywareProducts(&asList);
	DetectFirewallProducts(&fwList);

	while(!done) {

		Sleep(250);
	}

	UnregisterProductStateChanges();

    CoUninitialize();

    return 0;   // Program successfully completed.	
}