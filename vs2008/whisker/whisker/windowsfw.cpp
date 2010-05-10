/*
    Copyright (c) Microsoft Corporation

    SYNOPSIS

        Sample code for the Windows Firewall COM interface.
*/

#include "windowsfw.h"
#include <windows.h>
#include <process.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>
#include "eventdetection.h"

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

BOOL windowsFirewallRealtimeState = FALSE;

HRESULT WindowsFirewallInitialize(OUT INetFwProfile** fwProfile)
{
    HRESULT hr = S_OK;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;

    _ASSERT(fwProfile != NULL);

    *fwProfile = NULL;

    // Create an instance of the firewall settings manager.
    hr = CoCreateInstance(
            __uuidof(NetFwMgr),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwMgr),
            (void**)&fwMgr
            );
    if (FAILED(hr))
    {
        printf("CoCreateInstance failed: 0x%08lx\n", hr);
        goto error;
    }

    // Retrieve the local firewall policy.
    hr = fwMgr->get_LocalPolicy(&fwPolicy);
    if (FAILED(hr))
    {
        printf("get_LocalPolicy failed: 0x%08lx\n", hr);
        goto error;
    }

    // Retrieve the firewall profile currently in effect.
    hr = fwPolicy->get_CurrentProfile(fwProfile);
    if (FAILED(hr))
    {
        printf("get_CurrentProfile failed: 0x%08lx\n", hr);
        goto error;
    }

error:

    // Release the local firewall policy.
    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    // Release the firewall settings manager.
    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return hr;
}

void WindowsFirewallCleanup(IN INetFwProfile* fwProfile)
{
    // Release the firewall profile.
    if (fwProfile != NULL)
    {
        fwProfile->Release();
    }
}

HRESULT WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn)
{
    HRESULT hr = S_OK;
    VARIANT_BOOL fwEnabled;

    _ASSERT(fwProfile != NULL);
    _ASSERT(fwOn != NULL);

    *fwOn = FALSE;

    // Get the current state of the firewall.
    hr = fwProfile->get_FirewallEnabled(&fwEnabled);
    if (FAILED(hr))
    {
        printf("get_FirewallEnabled failed: 0x%08lx\n", hr);
        goto error;
    }

    // Check to see if the firewall is on.
    if (fwEnabled != VARIANT_FALSE)
    {
        *fwOn = TRUE;
    }

error:

    return hr;
}

HRESULT GetWindowsFirewallState(BOOL *fwOn) {
	HRESULT hr               = S_OK;
	INetFwProfile* fwProfile = NULL;

	// Retrieve the firewall profile currently in effect.
	hr = WindowsFirewallInitialize(&fwProfile);
	if (FAILED(hr))
	{
		printf("WindowsFirewallInitialize failed: 0x%08lx\n", hr);
		goto error;
	}

	_ASSERT(fwProfile != NULL);

	// Check to see if the firewall is off.
	hr = WindowsFirewallIsOn(fwProfile, fwOn);
	if (FAILED(hr))
	{
		printf("WindowsFirewallIsOn failed: 0x%08lx\n", hr);
		goto error;
	}

	error:

	// Release the firewall profile.
	WindowsFirewallCleanup(fwProfile);

	return hr;
}

unsigned __stdcall PollWindowsFirewallState(void* arg) {
  HANDLE timer  = (HANDLE)arg;
  BOOL newState = FALSE;

  while (1) {
    WaitForSingleObject(timer, INFINITE);

	GetWindowsFirewallState(&newState);

	if(windowsFirewallRealtimeState != newState) {

		ProductStateChangeOccurred((void *)EVENT_TYPE_MSFW);

		windowsFirewallRealtimeState = newState;
	}
  }

}

HRESULT RegisterMSFirewallChanges() {
	HANDLE timer = NULL;

	timer = CreateWaitableTimer(0, false, 0);
	LARGE_INTEGER li;
	const int unitsPerSecond = 10 * 1000 * 1000;

	li.QuadPart=-(5*unitsPerSecond);

	SetWaitableTimer(timer, &li, 5000, 0, 0, false);

	_beginthreadex(0, 0, PollWindowsFirewallState, (void *)timer, 0, 0);

	return S_OK;
}
