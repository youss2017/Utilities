#include "CppUtility.hpp"
#include "Socket.hpp"
#include <thread>
#include <chrono>
#include <windows.h>
#include <iostream>

#define MULITCAST_GROUP "239.211.208.140"
#define MULTICAST_PORT 2500

void simple_multicast_sender() {
	sw::Startup();
	sw::Socket sender(sw::SocketType::UDP);
	while (true) {
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
		std::string msg = "Hello! " + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count());
		sender.SendTo(msg.c_str(), msg.size(), MULITCAST_GROUP, MULTICAST_PORT);
	}
}

void simple_multicast_listener() {
	sw::Startup();
	sw::Socket lister(sw::SocketType::UDP);
	lister.Bind(sw::SocketInterface::Any, MULTICAST_PORT).JoinMulticastGroup(MULITCAST_GROUP);
	while (true) {
		char buf[256]{};
		sw::Endpoint source;
		lister.RecvFrom(buf, 256, &source);
		LOG(INFO, "Lister recieved {0} from {1}", buf, source.ToString());
	}
}

int main() {

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