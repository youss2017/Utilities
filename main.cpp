#include "CppUtility.hpp"
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#pragma comment(lib, "Mfplat.lib")
#pragma comment(lib, "mf.lib")
using namespace std;

int main() {

	CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	MFStartup(MF_VERSION);
    
	UINT32 count = 0;

	IMFAttributes* pConfig = NULL;
	IMFActivate** ppDevices = NULL;

	// Create an attribute store to hold the search criteria.
	HRESULT hr = MFCreateAttributes(&pConfig, 1);

    // Request video capture devices.
    if (SUCCEEDED(hr))
    {
        hr = pConfig->SetGUID(
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID
        );
    }

    // Enumerate the devices,
    if (SUCCEEDED(hr))
    {
        hr = MFEnumDeviceSources(pConfig, &ppDevices, &count);
    }
    IMFMediaSource** ppSource = nullptr;
    ppDevices[0]->ActivateObject(IID_PPV_ARGS(ppSource));
    
    wchar_t szName[128]{};
    ppDevices[0]->GetString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, szName, sizeof(szName)/sizeof(szName[0]), nullptr);

    string name = cpp::ToAsciiString(szName);
    LOG(INFO, "{}", name);

    CoTaskMemFree(ppDevices);

	return 0;
}