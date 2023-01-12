#include "CppUtility.hpp"
#include "Socket.hpp"
#include <thread>
#include <chrono>
#include <windows.h>
#include <iostream>
#include <random>
#include "stb.h"

// Note: This file is used only for testing and debugging.

#define MULITCAST_GROUP "239.5.6.8"
#define MULTICAST_PORT 2500

void simple_multicast_sender() {
	sw::Startup();
	sw::Socket s(sw::SocketType::UDP);
	s.Bind(sw::SocketInterface::Any, 4000).SetBroadcastOption(true);
}

void simple_multicast_listener() {
	sw::Startup();
	sw::Socket lister(sw::SocketType::UDP);
	lister.Bind(sw::SocketInterface::Any, MULTICAST_PORT).JoinMulticastGroup(MULITCAST_GROUP).SetMulticastLoopOption(false);
	while (true) {
		char buf[256]{};
		sw::Endpoint source;
		lister.RecvFrom(buf, 256, &source);
		LOG(INFO, "Lister recieved {0} from {1}", buf, source.ToString());
	}
}

int main() {
	sw::Startup();

	sw::Socket s(sw::SocketType::TCP);
	s.Bind(sw::SocketInterface::CustomInterface, 0, "127.10.20.30").Listen(1000);
	
	auto& ep = s.GetEndpoint();
	
	LOG(INFO, "Test {2:.2lf} {0} {}", "Oxygen", "Hydrogen", 10.5);
	LOG(INFO, "Bound at {0}", ep.ToString());
	LOG(INFO, "Test {0F} OK {1}", 15, 20);

	auto conn = s.Accept();

	while (true) {
		char request[5]{};
		if (conn.Recv(request, 4, false) > 0) {
			if (cpp::StartsWith(request, "req")) {
				char dateTime[256]{};
				auto traw = time(nullptr);
				tm t;
				gmtime_s(&t, &traw);
				strftime(dateTime, 256, "%x %X %p", &t);
				std::random_device rd;
				auto msg = cpp::Format("CTime {0} Date {1} Seed {2}\r\n", time(nullptr), dateTime, rd());
				conn.Send(msg);
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}
			else {
				auto msg = cpp::Format("HTTP/1.1 200 OK\r\nContent-Length: {0}\r\nContent-Type: text/html\r\n\r\n<b>200 OK</b>", strlen("<b>200 OK</b>"));
				conn.Send(msg);
			}
		}
		else if (!conn.IsConnected()) {
			conn = s.Accept();
		}
	}

	LOG(INFOBOLD, "DISCONNECTED.");

	cpp::Logger::GetGlobalLogger().Options.ShowMessageBoxOnError = true;
	cpp::Logger::GetGlobalLogger().Options.DebugBreakOnError = true;

	// Logger testing
	int8_t _i8x = INT8_MAX;
	int16_t _i16x = INT16_MAX;
	int32_t _i32x = INT32_MAX;
	int64_t _i64x = INT64_MAX;
	uint8_t _u8x = UINT8_MAX;
	uint16_t _u16x = UINT16_MAX;
	uint32_t _u32x = UINT32_MAX;
	uint64_t _u64x = UINT64_MAX;

	int8_t _i8m = INT8_MIN;
	int16_t _i16m = INT16_MIN;
	int32_t _i32m = INT32_MIN;
	int64_t _i64m = INT64_MIN;

	float _f32m = FLT_MIN;
	float _f32x = FLT_MAX;
	double _f64m = DBL_MIN;
	double _f64x = DBL_MAX;
	const char* _sample = "TEXT SAMPLE";

	LOG(INFO, "INT8 {0} {1}", _i8m, _i8x);
	LOG(INFO, "INT16 {0} {1}", _i16m, _i16x);
	LOG(INFO, "INT32 {0} {1}", _i32m, _i32x);
	LOG(INFO, "INT64 {0} {1}", _i64m, _i64x);

	LOG(INFO, "UINT8 {0}", _u8x);
	LOG(INFO, "UINT16 {0}", _u16x);
	LOG(INFO, "UINT32 {0}", _u32x);
	LOG(INFO, "UINT64 {0}", _u64x);

	LOG(INFO, "FLOAT32 {0:%.3f} {1}", _f32m, _f32x);
	LOG(INFO, "FLOAT64 {0} {1}", _f64m, _f64x);
	LOG(INFO, "TEXT {{{0}}}", _sample);
	LOG(INFO, "POINTER {0}", (void*)_sample);

	LOG(WARNING, "{0:%.2f}  {1:%09.3f}", 3.145677, 4917.24);

	LOG(ERR, "Catastropic I/O Error on PCI-e bus.");

	std::this_thread::sleep_for(std::chrono::days(10));

	auto adapters = sw::Socket::EnumerateNetworkAdapters();
	for (auto& a : adapters) {
		LOG(INFO, "\n{0}", std::string(a));
	}

	std::thread x(simple_multicast_listener);
	x.detach();
	simple_multicast_sender();

	int xx;
	std::cin >> xx;
}