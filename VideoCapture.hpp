#pragma once
#include <string>
#include <vector>

// create an empty cpp file and define
// note you must also compile CppUtility
//#define VIDEO_CAPTURE_IMPLEMENTATION

#define VIDEO_CAPTURE_NAMESPACE vc

#ifndef _WIN32
#error "Not Supported"
#endif

#ifdef VIDEO_CAPTURE_IMPLEMENTATION
#ifdef _WIN32
#include <Windows.h>
#include <mfapi.h>
#include <Mfidl.h>
#include <mfreadwrite.h>
#include <wrl/client.h>
#include <ranges>
#pragma comment(lib, "Mfplat.lib")
#pragma comment(lib, "Mf.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "Mfreadwrite.lib")
#include "CppUtility.hpp"
#endif
#endif

namespace VIDEO_CAPTURE_NAMESPACE {

	struct OSVideoCtx;

	// only for windows
	bool LoadCOM();

	struct Resolution {
		int32_t Width;
		int32_t Height;
	};

	struct CaptureVideoDevice {
		std::string Name;
		std::vector<Resolution> SupportedResolutions;
		std::vector<int32_t> MinFramerate;
		std::vector<int32_t> MaxFramerate;
		OSVideoCtx* Ctx{};

		CaptureVideoDevice() = default;
		~CaptureVideoDevice();
		CaptureVideoDevice(CaptureVideoDevice&&) noexcept;
		CaptureVideoDevice& operator=(CaptureVideoDevice&&) noexcept;
		CaptureVideoDevice(const CaptureVideoDevice&);
	};

	class CaptureVideoInterface {
	public:
		CaptureVideoInterface(const CaptureVideoDevice& captureDevice);
		//~VideoDeviceInterface();
		//VideoDeviceInterface(VideoDeviceInterface&) = delete;
		//VideoDeviceInterface(VideoDeviceInterface&&) noexcept;
		//VideoDeviceInterface& operator=(VideoDeviceInterface&&) noexcept;

		static std::vector<CaptureVideoDevice> Enumerate();

		Resolution GetResolution();
		void SetResolution(int32_t width, int32_t height);

		//void SetFramerate();
		//void SetFormat();

		//void StartCapture();
		//void StopCapture();

		void Capture(void* pOutData, size_t bufferSize);

		//void SetCaptureCallback();

	private:
		CaptureVideoDevice CaptureDevice;
	};

#ifdef VIDEO_CAPTURE_IMPLEMENTATION
        #ifdef _WIN32
	using namespace Microsoft::WRL;

	bool LoadCOM() {
		if(SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) && SUCCEEDED(MFStartup(MF_VERSION))) return true;
		return false;
	}

	struct OSVideoCtx {
		ComPtr<IMFActivate> pDevice;
		ComPtr<IMFMediaSource> pSource;
		ComPtr<IMFPresentationDescriptor> pDescriptor;
		ComPtr<IMFStreamDescriptor> pStreamDescriptor;
		ComPtr<IMFMediaTypeHandler> pTypeHandler;
		ComPtr<IMFSourceReader> pReader;
		ComPtr<IMFSample> pSample;
		ComPtr<IMFAttributes> pSampleAttribute;
	};

	CaptureVideoDevice::~CaptureVideoDevice() {
		if (Ctx)
			delete Ctx;
	}

	CaptureVideoDevice::CaptureVideoDevice(CaptureVideoDevice&& move) noexcept :
		Name(std::exchange(move.Name, "")),
		SupportedResolutions(std::exchange(move.SupportedResolutions, {})),
		MinFramerate(std::exchange(move.MinFramerate, {})),
		MaxFramerate(std::exchange(move.MaxFramerate, {})),
		Ctx(std::exchange(move.Ctx, nullptr))
	{}

	CaptureVideoDevice::CaptureVideoDevice(const CaptureVideoDevice& copy) :
		Name(copy.Name),
		SupportedResolutions(copy.SupportedResolutions),
		MinFramerate(copy.MinFramerate),
		MaxFramerate(copy.MaxFramerate)
	{
		Ctx = new OSVideoCtx;
		if (copy.Ctx) {
			Ctx->pDevice = copy.Ctx->pDevice;
			Ctx->pSource = copy.Ctx->pSource;
			Ctx->pDescriptor = copy.Ctx->pDescriptor;
			Ctx->pStreamDescriptor = copy.Ctx->pStreamDescriptor;
			Ctx->pTypeHandler = copy.Ctx->pTypeHandler;
			Ctx->pReader = copy.Ctx->pReader;
			Ctx->pSample = copy.Ctx->pSample;
			Ctx->pSampleAttribute = copy.Ctx->pSampleAttribute;
		}
	}

	CaptureVideoDevice& CaptureVideoDevice::operator=(CaptureVideoDevice&& move) noexcept
	{
		if (this == &move) return *this;
		this->~CaptureVideoDevice();
		Name = (std::exchange(move.Name, ""));
		SupportedResolutions = (std::exchange(move.SupportedResolutions, {}));
		MinFramerate = (std::exchange(move.MinFramerate, {}));
		MaxFramerate = (std::exchange(move.MaxFramerate, {}));
		Ctx = (std::exchange(move.Ctx, nullptr));
		return *this;
	}

	std::vector<CaptureVideoDevice> CaptureVideoInterface::Enumerate() {
		ComPtr<IMFAttributes> pConfig;
		IMFActivate** ppDevice = nullptr;
		uint32_t deviceCount{};
		MFCreateAttributes(&pConfig, 1);

		pConfig->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

		MFEnumDeviceSources(pConfig.Get(), &ppDevice, &deviceCount);
		if (deviceCount == 0) return {};

		std::vector<CaptureVideoDevice> ret;

		for (uint32_t i = 0; i < deviceCount; i++) {
			auto pDevice = ppDevice[i];
			wchar_t* szFriendlyName = nullptr;
			uint32_t length = 0;
			pDevice->GetAllocatedString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &szFriendlyName, &length);
			auto& item_ = ret.emplace_back();
			auto item = &item_;
			if (szFriendlyName == nullptr) {
				item->Name = "";
			}
			else {
				item->Name = cpp::ToAsciiString(szFriendlyName);
			}
			item->Ctx = new OSVideoCtx();
			item->Ctx->pDevice = pDevice;

			pDevice->ActivateObject(IID_PPV_ARGS(&item->Ctx->pSource));
			item->Ctx->pSource->CreatePresentationDescriptor(&item->Ctx->pDescriptor);

			BOOL selected{ false };
			item->Ctx->pDescriptor->GetStreamDescriptorByIndex(0, &selected, &item->Ctx->pStreamDescriptor);

			item->Ctx->pStreamDescriptor->GetMediaTypeHandler(&item->Ctx->pTypeHandler);

			DWORD count{};
			item->Ctx->pTypeHandler->GetMediaTypeCount(&count);

			for (DWORD i = 0; i < count; i++) {
				ComPtr<IMFMediaType> pMType;
				item->Ctx->pTypeHandler->GetMediaTypeByIndex(i, &pMType);

				PROPVARIANT var{};
				pMType->GetItem(MF_MT_FRAME_RATE_RANGE_MIN, &var);
				item->MinFramerate.push_back(var.intVal);
				pMType->GetItem(MF_MT_FRAME_RATE_RANGE_MAX, &var);
				item->MaxFramerate.push_back(var.intVal);
				pMType->GetItem(MF_MT_FRAME_SIZE, &var);
				int32_t width = (int32_t)var.cyVal.Hi;
				int32_t height = (int32_t)var.cyVal.Lo;
				if (std::ranges::count_if(item->SupportedResolutions, [=](auto& res) {
					return res.Width == width && res.Height == height;
					}) == 0) {
					item->SupportedResolutions.push_back({ width, height });
				}

			}
			std::ranges::sort(item->SupportedResolutions, [](auto& a, auto& b) {
				return a.Width > b.Width;
				});
			pDevice->ShutdownObject();
		}

		return ret;
	}

	CaptureVideoInterface::CaptureVideoInterface(const CaptureVideoDevice& captureDevice) : CaptureDevice(captureDevice)
	{

		auto& ctx = CaptureDevice.Ctx;
		ctx->pDevice->ActivateObject(IID_PPV_ARGS(&ctx->pSource));

		ComPtr<IMFAttributes> attributes;
		MFCreateAttributes(&attributes, 1);
		attributes->SetUINT32(MF_READWRITE_DISABLE_CONVERTERS, TRUE);

		MFCreateSourceReaderFromMediaSource(ctx->pSource.Get(), nullptr, &ctx->pReader);
		MFCreateAttributes(&ctx->pSampleAttribute, 1);
	}

	namespace internal {
		Resolution GetResolutionFromType(IMFMediaType* type) {
			PROPVARIANT var{};
			type->GetItem(MF_MT_FRAME_SIZE, &var);
			return { int32_t(var.cyVal.Hi), int32_t(var.cyVal.Lo) };
		}
	}

	Resolution CaptureVideoInterface::GetResolution()
	{
		ComPtr<IMFMediaType> type;
		CaptureDevice.Ctx->pTypeHandler->GetCurrentMediaType(&type);
		return internal::GetResolutionFromType(type.Get());
	}

	void CaptureVideoInterface::SetResolution(int32_t width, int32_t height)
	{
		if (std::ranges::count_if(CaptureDevice.SupportedResolutions, [=](auto& item) { return item.Width == width && item.Height == height; }) == 0) {
			LOGEXCEPT("Could not set resolution because {0} does not support {1}x{2}", CaptureDevice.Name, width, height);
		}
		DWORD count{};
		ComPtr<IMFMediaType> currentType;
		CaptureDevice.Ctx->pTypeHandler->GetCurrentMediaType(&currentType);
		HRESULT hr = MFSetAttributeSize(currentType.Get(), MF_MT_FRAME_SIZE, width, height);
		currentType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB8);
		CaptureDevice.Ctx->pTypeHandler->SetCurrentMediaType(currentType.Get());
		// MF_MT_SUBTYPE
	}

	void CaptureVideoInterface::Capture(void* pOutData, size_t bufferSize)
	{
		auto ctx = CaptureDevice.Ctx;
		do {
			DWORD streamIndex{};
			DWORD streamFlags{};
			LONGLONG Time{};
			ctx->pReader->ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &streamIndex, &streamFlags, &Time, &ctx->pSample);
			LOG(INFOBOLD, "{0} {1:%x} # {2}", streamIndex, streamFlags, (size_t)Time);
		} while (ctx->pSample.Get() == nullptr);
		DWORD bufferCount{};
		ctx->pSample->GetBufferCount(&bufferCount);
			ComPtr<IMFMediaBuffer> buffer;
			ctx->pSample->GetBufferByIndex(0, &buffer);
			ComPtr<IMF2DBuffer> buffer2d;
			buffer->QueryInterface<IMF2DBuffer>(&buffer2d);
			buffer2d->ContiguousCopyTo((BYTE*)pOutData, (DWORD)bufferSize);
			//DWORD size = bufferSize;
			//BYTE* temp;
			//DWORD xxx{};
			//buffer->Lock(&temp, (DWORD*)&size, &xxx);
			//LOG(INFO, "Buffer Ptr {0:%p} and Buffer Size {1}", temp, (uint64_t)size);
			//memcpy(((char*)pOutData) + offset, temp, xxx);
			//buffer->Unlock();
			//offset += xxx;
	}

#endif
#endif

}
