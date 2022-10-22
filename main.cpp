#include "CppUtility.hpp"
#include "Socket.hpp"
#include <thread>
#include <chrono>
#include <windows.h>

int main() {
	sw::Startup();
	sw::Socket s(sw::SocketType::UDP);
	s.Bind(sw::SocketInterface::Any, 4000).EnableBroadcast();

	while (true) {
		s.SendTo("hello", 5, "192.168.1.255", 3000);
		int x = WSAGetLastError();
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}


	int x;
	std::cin >> x;
}