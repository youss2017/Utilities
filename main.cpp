#include "CppUtility.hpp"
#include "Socket.hpp"
#include <thread>
#include <chrono>
#include <windows.h>

int main() {
	sw::Startup();

	auto adapters = sw::Socket::EnumerateNetworkAdapters();
	for (auto& a : adapters) {
		LOG(INFO, "\n{0}", std::string(a));
	}
	return 0;

	sw::Socket s(sw::SocketType::UDP);
	s.Bind(sw::SocketInterface::Any, 4000).EnableBroadcast();

	while (true) {
		auto b = s.SendTo("hello", 5, "255.255.255.255", 3000);
		int e = WSAGetLastError();
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
		LOG(INFO, "{0} Send Bytes, Error {1}", b, e);
	}


	int x;
	std::cin >> x;
}