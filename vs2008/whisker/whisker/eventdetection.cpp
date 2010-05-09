#define _WIN32_DCOM
#include "eventdetection.h"
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <netfw.h>
#include <windows.h>
#include <Wscapi.h>
#include <stdio.h>
#include <list>
#include "productinfo.h"
#include "windowsfw.h"

using namespace std;

#pragma comment(lib, "wbemuuid.lib")


/*#define PRODUCT_CODE_SECURITY_PROVIDER 0x00FF
#define PRODUCT_CODE_SCANNER_SETTINGS 0x0000FF
#define PRODUCT_CODE_DAT_FILE_UPDATED 0x000000FF*/

#define REAL_TIME_PROTECTION_ENABLED 0x00001000
#define DAT_FILE_OUT_OF_DATE 0x00000010
#define DAT_FILE_NOTIFIED_USER 0x00000001

// TODO: Make registration thread-specific instead of global.

static struct eventNotificationContext {
	bool av;
	bool as;
	bool fw;
	bool processedEvents;
	bool rawEvents;

	list <struct productInfo> avList;
	list <struct productInfo> asList;
	list <struct productInfo> fwList;

	void (*EventCallback)(list<struct productChangedEvent> &changedProducts);
}eventContext;

// This is used internally to keep track of when the event-based
// lists need updating.  We only need to update when an event occurs
static bool updateEventQueue = true;

// These should only be used internally by eventdetection.cpp
static bool registeredForEvents    = false;
static HANDLE callbackRegistration = NULL;

string datFileGuess(int productState) {
	string guessString;

	if(productState & DAT_FILE_OUT_OF_DATE) {
		guessString += "DAT File Out of Date ";
	} else {
		guessString += "DAT File Up to Date ";
	}

	if(productState & DAT_FILE_NOTIFIED_USER) {
		guessString += "DAT File Notified User ";
	}

	return guessString;
}

string scannerActiveGuess(int productState) {
	string guessString;

	if(productState & REAL_TIME_PROTECTION_ENABLED) {
		guessString += "Enabled ";
	}

	if(!(productState & REAL_TIME_PROTECTION_ENABLED)) {
		guessString += "Disabled ";
	}

	return guessString;
}

string securityProviderGuess(int productState) {
string providerGuess;

	if((productState >> 16) & WSC_SECURITY_PROVIDER_FIREWALL) {
		providerGuess += "Firewall ";
	}

	if((productState >> 16)& WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) {
		providerGuess += "AutoUpdate ";
	}

	if((productState >> 16) & WSC_SECURITY_PROVIDER_ANTIVIRUS) {
		providerGuess += "AntiVirus ";
	}

	if((productState >> 16) & WSC_SECURITY_PROVIDER_ANTISPYWARE) {
		providerGuess += "AntiSpyware ";
	}

	if((productState >> 16) & WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) {
		providerGuess += "InternetSettings ";
	}

	if((productState >> 16) & WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) {
		providerGuess += "UAC ";
	}

	if((productState >> 16) & WSC_SECURITY_PROVIDER_SERVICE) {
		providerGuess += "Service ";
	}

	if((productState >> 16) & WSC_SECURITY_PROVIDER_NONE) {
		providerGuess += "None ";
	}

	return providerGuess;
}

void WINAPI ProductStateChangeOccurred(void *param) {
	WHISKER_EVENT_DETECTION_TYPE eventType = (WHISKER_EVENT_DETECTION_TYPE)(int)param;
	char eventTypeName[32]                = {0};
	list <struct productInfo> productList;
	list <struct productInfo>::iterator currentProduct;
	list <struct productChangedEvent> productEventList;
	list<struct productInfo>::iterator cachedProduct;
	struct productChangedEvent productEvent;

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

	// Detect products here.
	DetectAntiVirusProducts(&productList);
	DetectAntiSpywareProducts(&productList);
	DetectFirewallProducts(&productList);

	// If we're supposed to filter events, then queue the product changes
	// for post-processing.
	if(eventContext.processedEvents) {
		list<struct productInfo> *eventList;

		// Figure out which product changed and what changed.
		currentProduct = productList.begin();

		while(currentProduct != productList.end()) {
			bool productFound = false;

			productEvent.productInfo = *currentProduct;

			// Figure out what type of product it is
			switch(currentProduct->productType) {
				case PRODUCT_TYPE_AV:
					eventList = &eventContext.avList;
					break;
				case PRODUCT_TYPE_AS:
					eventList = &eventContext.asList;
					break;
				case PRODUCT_TYPE_FW:
					eventList = &eventContext.fwList;
					break;
				default:
					printf("Bug: Unknown product type at %s:%d\n", __FUNCTION__, __LINE__);
			};

			cachedProduct = eventList->begin();

			while(cachedProduct != eventList->end()) {
				// Find the right product.
				if(currentProduct->displayName == cachedProduct->displayName) {
					// A little extra checking never hurt anyone
					if(currentProduct->productType == cachedProduct->productType) {

						productFound = true;

						// If the product is still present, then we should mark it.

						// This is for detecting new products.
						currentProduct->productStillInstalled = true;

						// This is for detecting stale products.
						cachedProduct->productStillInstalled  = true;

						if(currentProduct->productState != cachedProduct->productState) {
							int stateChange = currentProduct->productState ^ cachedProduct->productState;

							printf("Product states don't match! 0x%08X/0x%08X Delta: 0x%08X\n", 
								currentProduct->productState, 
								cachedProduct->productState, 
								stateChange);

							
							if(stateChange & REAL_TIME_PROTECTION_ENABLED) {
								if(currentProduct->productState & REAL_TIME_PROTECTION_ENABLED) {
									productEvent.eventType = PRODUCT_REALTIME_ENABLE_EVENT;
								} else {
									productEvent.eventType = PRODUCT_REALTIME_DISABLE_EVENT;
								}

								productEvent.productInfo = *currentProduct;

								productEventList.push_back(productEvent);

								stateChange ^= REAL_TIME_PROTECTION_ENABLED;
							}

							if(stateChange & DAT_FILE_OUT_OF_DATE) {
								if(currentProduct->productState & DAT_FILE_OUT_OF_DATE) {
									productEvent.eventType = PRODUCT_DEFINITIONS_OUT_OF_DATE_EVENT;
								} else {
									productEvent.eventType = PRODUCT_DEFINITIONS_UP_TO_DATE_EVENT;
								}

								productEvent.productInfo = *currentProduct;

								productEventList.push_back(productEvent);

								stateChange ^= DAT_FILE_OUT_OF_DATE;
							}

							if(stateChange > 0) {
								printf("Unaccounted for state change: 0x%08X\n", stateChange);
							}

							// Now that we've processed the changes, we can update the cached copy.
							*cachedProduct = *currentProduct;
						}

					}
				}

				cachedProduct++;
			}

			if(productFound == false) {
				// Looks like we found a new product!
				printf("Found a new product!\n");

				currentProduct->productStillInstalled = true;

				productEvent.eventType   = PRODUCT_INSTALL_EVENT;

				productEvent.productInfo = *currentProduct;

				productEventList.push_back(productEvent);

				// Figure out what type of product it is
				switch(currentProduct->productType) {
					case PRODUCT_TYPE_AV:
						eventContext.avList.push_back(*currentProduct);
						break;
					case PRODUCT_TYPE_AS:
						eventContext.asList.push_back(*currentProduct);
						break;
					case PRODUCT_TYPE_FW:
						eventContext.fwList.push_back(*currentProduct);
						break;
					default:
						printf("Bug: Unknown product type at %s:%d\n", __FUNCTION__, __LINE__);
				};
			}

			currentProduct++;
		}

		// Now run through the list one more time looking for expired products

		// Check AV products for expired entries.
		cachedProduct = eventContext.avList.begin();

		while(cachedProduct != eventContext.avList.end()) {

			if(cachedProduct->productStillInstalled == false) {
				printf("AV Product removed!\n");

				productEvent.eventType   = PRODUCT_UNINSTALL_EVENT;

				productEvent.productInfo = *cachedProduct;

				productEventList.push_back(productEvent);

				eventContext.avList.erase(cachedProduct++);
			} else {
				// Reset it for the next event.
				cachedProduct->productStillInstalled = false;
				cachedProduct++;
			}
		}

		// Check AV products for expired entries.
		cachedProduct = eventContext.asList.begin();

		while(cachedProduct != eventContext.asList.end()) {

			if(cachedProduct->productStillInstalled == false) {

				productEvent.eventType   = PRODUCT_UNINSTALL_EVENT;

				productEvent.productInfo = *cachedProduct;

				productEventList.push_back(productEvent);

				printf("AS Product removed!\n");

				eventContext.asList.erase(cachedProduct++);
			} else {
				// Reset it for the next event.
				cachedProduct->productStillInstalled = false;
				cachedProduct++;
			}
		}

		// Check AV products for expired entries.
		cachedProduct = eventContext.fwList.begin();

		while(cachedProduct != eventContext.fwList.end()) {

			if(cachedProduct->productStillInstalled == false) {
				printf("FW Product removed!\n");

				productEvent.eventType   = PRODUCT_UNINSTALL_EVENT;

				productEvent.productInfo = *cachedProduct;

				productEventList.push_back(productEvent);

				eventContext.fwList.erase(cachedProduct++);
			} else {
				// Reset it for the next event.
				cachedProduct->productStillInstalled = false;
				cachedProduct++;
			}
		}

	}

	if(eventContext.rawEvents) {
		// We needed a placeholder event type so that
		// we could deliver filterd and unfiltered
		// events through the same callback
		productEvent.eventType = PRODUCT_RAW_EVENT;

		// Otherwise, just deliver them.
		currentProduct = productList.begin();

		while(currentProduct != productList.end()) {
			productEvent.productInfo = *currentProduct;

			productEventList.push_back(productEvent);

			currentProduct++;
		}
	}

	// Send the event list.
	if(eventContext.EventCallback != NULL) {
		if(productEventList.size() > 0) {
			eventContext.EventCallback(productEventList);
		}
	}
}

HRESULT UnregisterProductStateChanges() {
	HRESULT hres = S_OK;

	if(registeredForEvents == true) {
		hres = WscUnRegisterChanges(callbackRegistration);

		memset(&eventContext, 0x0, sizeof(struct eventNotificationContext));

		registeredForEvents = false;
	}

	return hres;
}

// detect product change
// queue event (fifo)
// compare each queued event with master list
// if product doesn't exist, issue a product installed event
// queue product for addition to master list (performance reasons - Adding it immediately could slow down checks.)
// if product does exist, check productState
// if product state is different, issue appropriate event(s). (tbd based on state data).
// mark product as still present
// at the end of all queued events iterate master list and check for non-present items... this means the product(s) in question were uninstalled.
HRESULT RegisterProductStateChanges(void (*productStateChangeCallback)(list<struct productChangedEvent> &changedProducts), int registrationType) {
	HRESULT hres = S_OK;

	// Register for WSC Notifications
	if(registrationType == EVENT_REGISTRATION_TYPE_NONE) {
		return UnregisterProductStateChanges();
	}

	// Update the products that we want to register for:
	eventContext.av              = ((registrationType & EVENT_REGISTRATION_TYPE_AV) != 0);
	eventContext.as              = ((registrationType & EVENT_REGISTRATION_TYPE_AS) != 0);
	eventContext.fw              = ((registrationType & EVENT_REGISTRATION_TYPE_FW) != 0);
	eventContext.rawEvents       = ((registrationType & EVENT_REGISTRATION_TYPE_RAW) != 0);
	eventContext.processedEvents = ((registrationType & EVENT_REGISTRATION_TYPE_PROCESSED) != 0);

	// Set up the caller's callback
	eventContext.EventCallback = productStateChangeCallback;

	if(registeredForEvents == true) {
		// Just update the product type map and callback.

		return S_OK;
	}

	// Prime the context with current information
	DetectAntiVirusProducts(&eventContext.avList);
	DetectAntiSpywareProducts(&eventContext.asList);
	DetectFirewallProducts(&eventContext.fwList);

	// We're not registered yet, so turn all the checkers on.
	hres = WscRegisterForChanges(
		NULL, 
		&callbackRegistration, 
		(LPTHREAD_START_ROUTINE)ProductStateChangeOccurred, 
		(PVOID)EVENT_TYPE_WSC);

	// Now setup non-wsc product detection
	// MS Firewall
	RegisterMSFirewallChanges();

	registeredForEvents = true;

	return S_OK;
}

HRESULT QuerySecurityCenter2Products(char *query, list<struct productInfo> *productList, WHISKER_PRODUCT_TYPE productType) {
    HRESULT hres;
    
    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        return hres;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices *pSvc = NULL;
	
    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
         _bstr_t(L"ROOT\\SECURITYCENTER2"), // Object path of WMI namespace
         NULL,                    // User name. NULL = current user
         NULL,                    // User password. NULL = current
         0,                       // Locale. NULL indicates current
         NULL,                    // Security flags.
         0,                       // Authority (e.g. Kerberos)
         0,                       // Context object 
         &pSvc                    // pointer to IWbemServices proxy
         );
    
    if (FAILED(hres))
    {
        cout << "Could not connect to ROOT\\SECURITYCENTER2. Error code = 0x" 
             << hex << hres << endl;
        pLoc->Release();     
        return hres;                // Program has failed.
    }

    //cout << "Connected to ROOT\\SECURITYCENTER2 WMI namespace" << endl;


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
       pSvc,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name 
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x" 
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();     
        return 1;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"), 
        bstr_t(query),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if (FAILED(hres))
    {
        cout << "Query '" << query << "' failed."
            << " Error code = 0x" 
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        return hres;               // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------
    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;
   
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
            &pclsObj, &uReturn);

        if(0 == uReturn)
        {
            break;
		}

		// A place to store our product data.
		struct productInfo product;
		memset(&product, 0x0, sizeof(struct productInfo));

        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);

        wcout << "Product Name: " << vtProp.bstrVal << endl;

		product.displayName = vtProp.bstrVal;

        VariantClear(&vtProp);

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		//wcout << "Instance GUID: " << vtProp.bstrVal << endl;

		product.instanceGuid = vtProp.bstrVal;

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productState", 0, &vtProp, 0, 0);

		int byte4 = (vtProp.intVal & 0xFF000000) >> 24;
		int byte3 = (vtProp.intVal & 0x00FF0000) >> 16;
		int byte2 = (vtProp.intVal & 0x0000FF00) >> 8;
		int byte1 = (vtProp.intVal & 0x000000FF);

		
		wcout << "Product State: " << dec << vtProp.intVal << endl;
		wcout << "Product State (hex): " << hex << vtProp.intVal << endl;
		wcout << "Byte 4: " << hex << byte4 << endl;
		wcout << "Byte 3: " << hex << byte3 << endl;
		wcout << "Byte 2: " << hex << byte2 << endl;
		wcout << "Byte 1: " << hex << byte1 << endl;
		wcout << "Product Type:  " << securityProviderGuess(vtProp.intVal).c_str() << endl;
		wcout << "Realtime Protection: " << scannerActiveGuess(vtProp.intVal).c_str() << endl;
		wcout << "DAT File: " << datFileGuess(vtProp.intVal).c_str() << endl;
		wcout << endl;
		

		product.productState = vtProp.intVal;

		if(product.productState & REAL_TIME_PROTECTION_ENABLED) {
			product.productEnabled = true;
		}

		if(!(product.productState & DAT_FILE_OUT_OF_DATE)) {
			product.productUptoDate = true;
		}

		product.productType = productType;

		productList->push_back(product);

		VariantClear(&vtProp);

        pclsObj->Release();
    }

    // Cleanup
    // ========
    
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();

	return S_OK;
}

HRESULT QuerySecurityCenterProducts(char *query, list<struct productInfo> *productList, WHISKER_PRODUCT_TYPE productType) {
    HRESULT hres;
    
    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        return hres;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices *pSvc = NULL;
	
    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
         _bstr_t(L"ROOT\\SECURITYCENTER"), // Object path of WMI namespace
         NULL,                    // User name. NULL = current user
         NULL,                    // User password. NULL = current
         0,                       // Locale. NULL indicates current
         NULL,                    // Security flags.
         0,                       // Authority (e.g. Kerberos)
         0,                       // Context object 
         &pSvc                    // pointer to IWbemServices proxy
         );
    
    if (FAILED(hres))
    {
        cout << "Could not connect to ROOT\\SECURITYCENTER. Error code = 0x" 
             << hex << hres << endl;
        pLoc->Release();     
        return hres;                // Program has failed.
    }

    //cout << "Connected to ROOT\\SECURITYCENTER WMI namespace" << endl;


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
       pSvc,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name 
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x" 
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();     
        return 1;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"), 
        bstr_t(query),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if (FAILED(hres))
    {
        cout << "Query '" << query << "' failed."
            << " Error code = 0x" 
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        return hres;               // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------
    IWbemClassObject *pclsObj;
    ULONG uReturn = 0;
   
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, 
            &pclsObj, &uReturn);

        if(0 == uReturn)
        {
            break;
		}

		// A place to store our product data.
		struct productInfo product;
		memset(&product, 0x0, sizeof(struct productInfo));

        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
        //wcout << "Product Name: " << vtProp.bstrVal << endl;

		product.displayName = vtProp.bstrVal;

        VariantClear(&vtProp);

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		//wcout << "Instance GUID: " << vtProp.bstrVal << endl;

		product.instanceGuid = vtProp.bstrVal;

		VariantClear(&vtProp);

        hr = pclsObj->Get(L"companyName", 0, &vtProp, 0, 0);
        //wcout << "Company Name: " << vtProp.bstrVal << endl;

		product.companyName = vtProp.bstrVal;

        VariantClear(&vtProp);

		hr = pclsObj->Get(L"productEnabled", 0, &vtProp, 0, 0);
		//wcout << "Product Enabled: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productEnabled = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productHasNotifiedUser", 0, &vtProp, 0, 0);
		//wcout << "Product Has Notified User: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productHasNotifiedUser = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productUptoDate", 0, &vtProp, 0, 0);
		//wcout << "Product Up to Date: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productUptoDate = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productWantWscNotifications", 0, &vtProp, 0, 0);
		//wcout << "Product Wants WSC Notifications: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productWantsWscNotifications = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"versionNumber", 0, &vtProp, 0, 0);
		//wcout << "Version Number: " << vtProp.bstrVal << endl;

		product.versionNumber = vtProp.bstrVal;

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productState", 0, &vtProp, 0, 0);

		int byte4 = (vtProp.intVal & 0xFF000000) >> 24;
		int byte3 = (vtProp.intVal & 0x00FF0000) >> 16;
		int byte2 = (vtProp.intVal & 0x0000FF00) >> 8;
		int byte1 = (vtProp.intVal & 0x000000FF);

		wcout << "Product State: " << dec << vtProp.intVal << endl;
		wcout << "Product State (hex): " << hex << vtProp.intVal << endl;
		wcout << "Byte 4: " << hex << byte4 << endl;
		wcout << "Byte 3: " << hex << byte3 << endl;
		wcout << "Byte 2: " << hex << byte2 << endl;
		wcout << "Byte 1: " << hex << byte1 << endl;
		wcout << "Product Guess:  " << securityProviderGuess(vtProp.intVal).c_str() << endl;
		wcout << "Realtime Guess: " << scannerActiveGuess(vtProp.intVal).c_str() << endl;
		wcout << "DAT File Guess: " << datFileGuess(vtProp.intVal).c_str() << endl;
		wcout << endl;

		product.productState = vtProp.intVal;

		product.productType = productType;

		productList->push_back(product);

		VariantClear(&vtProp);

        pclsObj->Release();
    }

    // Cleanup
    // ========
    
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();

	return S_OK;
}

HRESULT QueryOtherFirewallProducts(list<struct productInfo> *productList) {
    HRESULT hres             = S_OK;
    HRESULT comInit          = E_FAIL;
	INetFwProfile* fwProfile = NULL;
	BOOL fwState             = FALSE;
	struct productInfo product;

	memset(&product, 0x0, sizeof(struct productInfo));

	hres = GetWindowsFirewallState(&fwState);

	// This helps keep us in sync when polling state.
	windowsFirewallRealtimeState = fwState;

	product.companyName = L"Microsoft";
	product.displayName = L"Windows Firewall";
	product.productEnabled = (fwState != 0);
	product.productType = PRODUCT_TYPE_FW;

	// Set the product state.
	// This is crucial for events to work properly.
	product.productState = WSC_SECURITY_PROVIDER_FIREWALL << 16;

	if(product.productEnabled) {
		product.productEnabled = true;
		product.productState += REAL_TIME_PROTECTION_ENABLED;
	}

	//printf("Other Firewall Products: \n\n");

	//printf("Product Name: Windows Firewall\n");
	//printf("Realtime Protection: %s\n\n", (fwState == TRUE)? "Enabled" : "Disabled");

	productList->push_back(product);

	return hres;
}

HRESULT DetectAntiVirusProducts(list<struct productInfo> *avList) {
	HRESULT result = S_OK;
	char *query = "SELECT * from AntiVirusProduct";

	//printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = QuerySecurityCenter2Products(query, avList, PRODUCT_TYPE_AV);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = QuerySecurityCenterProducts(query, avList, PRODUCT_TYPE_AV);

	//printf("----- End Query: %s -----\n\n", query);

	// TODO: Any that don't show up?
	return result;
}

 HRESULT DetectAntiSpywareProducts(list<struct productInfo> *asList) {
	HRESULT result = S_OK;
	char *query = "SELECT * from AntiSpywareProduct";

	//printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = QuerySecurityCenter2Products(query, asList, PRODUCT_TYPE_AS);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = QuerySecurityCenterProducts(query, asList, PRODUCT_TYPE_AS);

	//printf("----- End Query: %s -----\n\n", query);

	// TODO: Windows Defender?
	return result;
}

HRESULT DetectFirewallProducts(list<struct productInfo> *fwList) {
	HRESULT result = S_OK;
	char *query = "SELECT * from FirewallProduct";

	//printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = QuerySecurityCenter2Products(query, fwList, PRODUCT_TYPE_FW);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = QuerySecurityCenterProducts(query, fwList, PRODUCT_TYPE_FW);

	//printf("----- End Query: %s -----\n\n", query);

	// TODO: Windows Firewall?
	result = QueryOtherFirewallProducts(fwList);

	return result;
}