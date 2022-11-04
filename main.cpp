#include "CppUtility.hpp"
#include "Socket.hpp"
#include <thread>
#include <chrono>
#include <windows.h>
#include <iostream>

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
	LOG(INFO, "Hello My Name is {0}, {1} and I'm {{{2}}}.", "Youssef", "Samwel", 18);

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