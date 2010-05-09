#ifndef __WINDOWS_FW_H__
#define __WINDOWS_FW_H__
#include <netfw.h>

extern BOOL windowsFirewallRealtimeState;

HRESULT WindowsFirewallInitialize(OUT INetFwProfile** fwProfile);
void WindowsFirewallCleanup(IN INetFwProfile* fwProfile);
HRESULT WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn);
HRESULT GetWindowsFirewallState(BOOL *fwOn);
HRESULT RegisterMSFirewallChanges();

#endif __WINDOWS_FW_H__