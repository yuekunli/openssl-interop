#pragma once

#ifndef WINVER
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#ifndef _WIN32_WINDOWS
#define _WIN32_WINDOWS 0x0410
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>



#define WIN32_LEAN_AND_MEAN

#define _CRT_SECURE_NO_DEPRECATE

#define _CRTDBG_MAP_ALLOC

#include <windows.h>
#include <winioctl.h>
#include <vector>
#include <iostream>
#include <atlstr.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include <powrprof.h>
#include <shlobj.h>
#include <Iads.h>
#include <AdsHlp.h>
#include <ActiveDS.h>
#include <sddl.h>
#include <TlHelp32.h>
#include <WS2TCPIP.h>
#include <WSPiApi.h>

#define SECURITY_WIN32

#include <security.h>
#include <Dsgetdc.h>
#include <LM.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Winnetwk.h>
#include <ATLComTime.h>
#include <time.h>
#include <sddl.h>
#include <DSRole.h>
#include <DbgHelp.h>
#include <winhttp.h>
#include <WinDNS.h>
#include <IcmpAPI.h>

#include <Winnls.h>


using namespace std;

#include "osrng.h"
#include "integer.h"
#include "nbtheory.h"
#include "dh.h"
#include "secblock.h"
#include "asn.h"
#include "oids.h"
#include "eccrypto.h"
#include "ecp.h"
#include "modes.h"
#include "des.h"
#include "eax.h"
#include "gcm.h"
#include "filters.h"

