#define _WIN32_DCOM
#include "eventdetection.h"
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#include <netfw.h>
#include <windows.h>
#include <Wscapi.h>
#include <stdio.h>
#include <queue>
#include "productinfo.h"
#include "windowsfw.h"

# pragma comment(lib, "wbemuuid.lib")

#define PRODUCT_STATE_BYTE4 0xFF000000
#define PRODUCT_STATE_BYTE3 0x00FF0000
#define PRODUCT_STATE_BYTE2 0x0000FF00
#define PRODUCT_STATE_BYTE1 0x000000FF

#define PRODUCT_CODE_SECURITY_PROVIDER 0x00FF
#define PRODUCT_CODE_SCANNER_SETTINGS 0x0000FF
#define PRODUCT_CODE_DAT_FILE_UPDATED 0x000000FF

#define REAL_TIME_SCAN_ENABLED 0x10
#define REAL_TIME_SCAN_UNKNOWN 0x01

#define DAT_FILE_UP_TO_DATE 0x00
#define DAT_FILE_OUT_OF_DATE 0x10
#define DAT_FILE_NOTIFIED_USER 0x01

string datFileGuess(int guess) {
	string guessString;

	if(guess == DAT_FILE_UP_TO_DATE) {
		guessString += "DAT File Current ";
	}

	if(guess & DAT_FILE_OUT_OF_DATE) {
		guessString += "DAT File Out of Date ";
	}

	if(guess & DAT_FILE_NOTIFIED_USER) {
		guessString += "DAT File Notified User ";
	}

	if(guess > 0x11) {
		printf("Unexpected value in dat file state guess.\n");
	}

	return guessString;
}

string scannerActiveGuess(int guess) {
	string guessString;

	if(guess & REAL_TIME_SCAN_ENABLED) {
		guessString += "Realtime Scanning Enabled ";
	}

	if(!(guess & REAL_TIME_SCAN_ENABLED)) {
		guessString += "Realtime Scanning Disabled ";
	}

	// If the real time scan byte contains anything other
	// than 0x10 or 0x00, then we have unknown bits set.
	if((guess != REAL_TIME_SCAN_ENABLED) && 
		(guess != 0)) {
		guessString += "Realtime Scanning Unknown Parameters ";
	}

	return guessString;
}

string securityProviderGuess(int provider) {
string providerGuess;

	if(provider & WSC_SECURITY_PROVIDER_FIREWALL) {
		providerGuess += "Firewall ";
	}

	if(provider & WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) {
		providerGuess += "AutoUpdate ";
	}

	if(provider & WSC_SECURITY_PROVIDER_ANTIVIRUS) {
		providerGuess += "AntiVirus ";
	}

	if(provider & WSC_SECURITY_PROVIDER_ANTISPYWARE) {
		providerGuess += "AntiSpyware ";
	}

	if(provider & WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) {
		providerGuess += "InternetSettings ";
	}

	if(provider & WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) {
		providerGuess += "UAC ";
	}

	if(provider & WSC_SECURITY_PROVIDER_SERVICE) {
		providerGuess += "Service ";
	}

	if(provider & WSC_SECURITY_PROVIDER_NONE) {
		providerGuess += "None ";
	}

	// Something changed or we're wrong...
	// 64 is the maximum in WSC_SECURITY_PROVIDER
	if(provider > 64) {
		printf("Value > 64 in WSC_SECURITY_PROVIDER guess variable.\n");
	}

	return providerGuess;
}

// TODO: Make registration thread-specific instead of global.

static struct eventMap {
	bool av;
	bool as;
	bool fw;
	bool filter;
	LPTHREAD_START_ROUTINE EventCallback;
}registeredEvents;

// This is used by the caller to determine when a refresh is necessary.
bool productCheckNeeded = true;

// These should only be used internally by eventdetection.cpp
static bool registeredForEvents    = false;
static HANDLE callbackRegistration = NULL;

void WINAPI ProductStateChangeOccurred(void *param) {
	WISKER_EVENT_DETECTION_TYPE eventType = (WISKER_EVENT_DETECTION_TYPE)(int)param;
	char eventTypeName[32]                = {0};

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

	// If we're supposed to filter events, then queue the product changes
	// for post-processing.
	if(registeredEvents.filter) {
		// TODO: Queue up products.
	} else {
		// Otherwise, just deliver them.
		if(registeredEvents.EventCallback != NULL) {
			registeredEvents.EventCallback((LPVOID)eventType);
		}
	}

	productCheckNeeded = true;
}

HRESULT UnregisterProductStateChanges() {
	HRESULT hres = S_OK;

	if(registeredForEvents == true) {
		hres = WscUnRegisterChanges(callbackRegistration);

		memset(&registeredEvents, 0x0, sizeof(struct eventMap));

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
HRESULT RegisterProductStateChanges(LPTHREAD_START_ROUTINE productStateChangeCallback, int registrationType) {
	HRESULT hres = S_OK;

	// Register for WSC Notifications
	if(registrationType == EVENT_REGISTRATION_TYPE_NONE) {
		return UnregisterProductStateChanges();
	}

	// Update the products that we want to register for:
	registeredEvents.av       = ((registrationType & EVENT_REGISTRATION_TYPE_AV)     != 0);
	registeredEvents.as       = ((registrationType & EVENT_REGISTRATION_TYPE_AS)     != 0);
	registeredEvents.fw       = ((registrationType & EVENT_REGISTRATION_TYPE_FW)     != 0);
	registeredEvents.filter   = ((registrationType & EVENT_REGISTRATION_TYPE_FILTER) != 0);

	// Set up the caller's callback
	registeredEvents.EventCallback = productStateChangeCallback;

	if(registeredForEvents == true) {
		// Just update the product type map and callback.

		return S_OK;
	}

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

HRESULT QuerySecurityCenter2Products(char *query) {
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

    cout << "Connected to ROOT\\SECURITYCENTER2 WMI namespace" << endl;


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
		wcout << "Instance GUID: " << vtProp.bstrVal << endl;

		product.instanceGuid = vtProp.bstrVal;

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productState", 0, &vtProp, 0, 0);

		int byte4 = (vtProp.intVal & PRODUCT_STATE_BYTE4) >> 24;
		int byte3 = (vtProp.intVal & PRODUCT_STATE_BYTE3) >> 16;
		int byte2 = (vtProp.intVal & PRODUCT_STATE_BYTE2) >> 8;
		int byte1 = (vtProp.intVal & PRODUCT_STATE_BYTE1);

		wcout << "Product State: " << vtProp.intVal << endl;
		wcout << "Product State (hex): " << hex << vtProp.intVal << endl;
		wcout << "Byte 4: " << hex << byte4 << endl;
		wcout << "Byte 3: " << hex << byte3 << endl;
		wcout << "Byte 2: " << hex << byte2 << endl;
		wcout << "Byte 1: " << hex << byte1 << endl;
		wcout << "Product Guess:  " << securityProviderGuess(byte3).c_str() << endl;
		wcout << "Realtime Guess: " << scannerActiveGuess(byte2).c_str() << endl;
		wcout << "DAT File Guess: " << datFileGuess(byte1).c_str() << endl;
		wcout << endl;

		product.productState = vtProp.intVal;

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

HRESULT QuerySecurityCenterProducts(char *query) {
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

    cout << "Connected to ROOT\\SECURITYCENTER WMI namespace" << endl;


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
		wcout << "Instance GUID: " << vtProp.bstrVal << endl;

		product.instanceGuid = vtProp.bstrVal;

		VariantClear(&vtProp);

        hr = pclsObj->Get(L"companyName", 0, &vtProp, 0, 0);
        wcout << "Company Name: " << vtProp.bstrVal << endl;

		product.companyName = vtProp.bstrVal;

        VariantClear(&vtProp);

		hr = pclsObj->Get(L"productEnabled", 0, &vtProp, 0, 0);
		wcout << "Product Enabled: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productEnabled = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productHasNotifiedUser", 0, &vtProp, 0, 0);
		wcout << "Product Has Notified User: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productHasNotifiedUser = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productUptoDate", 0, &vtProp, 0, 0);
		wcout << "Product Up to Date: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productUptoDate = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productWantWscNotifications", 0, &vtProp, 0, 0);
		wcout << "Product Wants WSC Notifications: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;

		product.productWantsWscNotifications = (vtProp.boolVal != 0);

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"versionNumber", 0, &vtProp, 0, 0);
		wcout << "Version Number: " << vtProp.bstrVal << endl;

		product.versionNumber = vtProp.bstrVal;

		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productState", 0, &vtProp, 0, 0);

		int byte4 = (vtProp.intVal & PRODUCT_STATE_BYTE4) >> 24;
		int byte3 = (vtProp.intVal & PRODUCT_STATE_BYTE3) >> 16;
		int byte2 = (vtProp.intVal & PRODUCT_STATE_BYTE2) >> 8;
		int byte1 = (vtProp.intVal & PRODUCT_STATE_BYTE1);

		wcout << "Product State: " << vtProp.intVal << endl;
		wcout << "Product State (hex): " << hex << vtProp.intVal << endl;
		wcout << "Byte 4: " << hex << byte4 << endl;
		wcout << "Byte 3: " << hex << byte3 << endl;
		wcout << "Byte 2: " << hex << byte2 << endl;
		wcout << "Byte 1: " << hex << byte1 << endl;
		wcout << "Product Guess:  " << securityProviderGuess(byte3).c_str() << endl;
		wcout << "Realtime Guess: " << scannerActiveGuess(byte2).c_str() << endl;
		wcout << "DAT File Guess: " << datFileGuess(byte1).c_str() << endl;
		wcout << endl;

		product.productState = vtProp.intVal;

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

HRESULT QueryOtherFirewallProducts() {
    HRESULT hr               = S_OK;
    HRESULT comInit          = E_FAIL;
	INetFwProfile* fwProfile = NULL;
	BOOL fwOn                = FALSE;

	GetWindowsFirewallState(&fwOn);

	// This helps keep us in sync when polling state.
	windowsFirewallRealtimeState = fwOn;

	printf("Other Firewall Products: \n\n");

	printf("Product Name: Windows Firewall\n");
	printf("Realtime Status: %s\n\n", (fwOn == TRUE)? "Enabled" : "Disabled");

	// If everything was peachy, set up a timer to periodically check this:

	return hr;
}

HRESULT DetectAntiVirusProducts() {
	HRESULT result = S_OK;
	char *query = "SELECT * from AntiVirusProduct";

	printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = QuerySecurityCenter2Products(query);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = QuerySecurityCenterProducts(query);

	printf("----- End Query: %s -----\n\n", query);

	// TODO: Any that don't show up?

	return result;
}

HRESULT DetectAntiSpywareProducts() {
	HRESULT result = S_OK;
	char *query = "SELECT * from AntiSpywareProduct";

	printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = QuerySecurityCenter2Products(query);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = QuerySecurityCenterProducts(query);

	printf("----- End Query: %s -----\n\n", query);

	// TODO: Windows Defender?

	return result;
}

HRESULT DetectFirewallProducts() {
	HRESULT result = S_OK;
	char *query = "SELECT * from FirewallProduct";

	printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = QuerySecurityCenter2Products(query);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = QuerySecurityCenterProducts(query);

	printf("----- End Query: %s -----\n\n", query);

	// TODO: Windows Firewall?
	result = QueryOtherFirewallProducts();

	return result;
}