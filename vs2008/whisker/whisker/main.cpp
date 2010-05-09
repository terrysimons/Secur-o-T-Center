#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#include <Wscapi.h>
#include <netfw.h>
#include <process.h>
#include "windowsfw.h"
#include "eventdetection.h"

bool done               = false;

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

HRESULT DisplaySecurityCenter2Products(char *query) {
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



        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
        wcout << "Product Name: " << vtProp.bstrVal << endl;
        VariantClear(&vtProp);

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		wcout << "Instance GUID: " << vtProp.bstrVal << endl;
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

HRESULT DisplaySecurityCenterProducts(char *query) {
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

        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
        wcout << "Product Name: " << vtProp.bstrVal << endl;
        VariantClear(&vtProp);

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		wcout << "Instance GUID: " << vtProp.bstrVal << endl;
		VariantClear(&vtProp);

        hr = pclsObj->Get(L"companyName", 0, &vtProp, 0, 0);
        wcout << "Company Name: " << vtProp.bstrVal << endl;
        VariantClear(&vtProp);

		hr = pclsObj->Get(L"productEnabled", 0, &vtProp, 0, 0);
		wcout << "Product Enabled: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;
		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productHasNotifiedUser", 0, &vtProp, 0, 0);
		wcout << "Product Has Notified User: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;
		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productUptoDate", 0, &vtProp, 0, 0);
		wcout << "Product Up to Date: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;
		VariantClear(&vtProp);

		hr = pclsObj->Get(L"productWantWscNotifications", 0, &vtProp, 0, 0);
		wcout << "Product Wants WSC Notifications: " << (vtProp.boolVal ? L"Yes" : L"No") << endl;
		VariantClear(&vtProp);

		hr = pclsObj->Get(L"versionNumber", 0, &vtProp, 0, 0);
		wcout << "Version Number: " << vtProp.bstrVal << endl;
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

HRESULT DisplayOtherFirewallProducts() {
    HRESULT hr               = S_OK;
    HRESULT comInit          = E_FAIL;
	INetFwProfile* fwProfile = NULL;
	BOOL fwOn                = FALSE;
	HANDLE timer             = NULL;

	GetWindowsFirewallState(&fwOn);

	// This helps keep us in sync when polling state.
	windowsFirewallRealtimeState = fwOn;

	printf("Other Firewall Products: \n\n");

	printf("Product Name: Windows Firewall\n");
	printf("Realtime Status: %s\n\n", (fwOn == TRUE)? "Enabled" : "Disabled");

	// If everything was peachy, set up a timer to periodically check this:
	timer = CreateWaitableTimer(0, false, 0);
	LARGE_INTEGER li;
	const int unitsPerSecond = 10 * 1000 * 1000;

	li.QuadPart=-(5*unitsPerSecond);

	SetWaitableTimer(timer, &li, 5000, 0, 0, false);

	_beginthreadex(0, 0, PollWindowsFirewallState, (void *)timer, 0, 0);

	return hr;
}


HRESULT DisplayAntiVirusProducts() {
	HRESULT result = S_OK;
	char *query = "SELECT * from AntiVirusProduct";

	printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = DisplaySecurityCenter2Products(query);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = DisplaySecurityCenterProducts(query);

	printf("----- End Query: %s -----\n\n", query);

	// TODO: Any that don't show up?

	return result;
}

HRESULT DisplayAntiSpywareProducts() {
	HRESULT result = S_OK;
	char *query = "SELECT * from AntiSpywareProduct";

	printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = DisplaySecurityCenter2Products(query);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = DisplaySecurityCenterProducts(query);

	printf("----- End Query: %s -----\n\n", query);

	// TODO: Windows Defender?

	return result;
}

HRESULT DisplayFirewallProducts() {
	HRESULT result = S_OK;
	char *query = "SELECT * from FirewallProduct";

	printf("----- Query: %s -----\n", query);

	// Get products for ROOT\\SECURITYCENTER2 namespace
	result = DisplaySecurityCenter2Products(query);

	// Get products for ROOT\\SECURITYCENTER namespace
	result = DisplaySecurityCenterProducts(query);

	printf("----- End Query: %s -----\n\n", query);

	// TODO: Windows Firewall?
	result = DisplayOtherFirewallProducts();

	return result;
}


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

int main(int argc, char **argv)
{
	HRESULT hres = S_OK;
	HANDLE callbackRegistration = NULL;

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

	// Final param gets passed to ProductStateChangeOccurred - It's specifc to our code.
	// See eventdetection.h
	hres = WscRegisterForChanges(
		NULL, 
		&callbackRegistration, 
		(LPTHREAD_START_ROUTINE)ProductStateChangeOccurred, 
		(PVOID)EVENT_TYPE_WSC);

	while(!done) {

		if(productCheckNeeded) {
			hres = DisplayAntiVirusProducts();
			hres = DisplayAntiSpywareProducts();
			hres = DisplayFirewallProducts();

			productCheckNeeded = false;;
		}

		Sleep(250);
	}

	WscUnRegisterChanges(callbackRegistration);

    CoUninitialize();


    return 0;   // Program successfully completed.	
}