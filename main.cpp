#include "CppUtility.hpp"
#include "Socket.hpp"
#include <thread>
#include <chrono>
#include <windows.h>

int main() {
	sw::Startup();

	std::cout << ut::Format("Hello My Name is {0}, {1} and I'm {{{2}}}.", "Youssef", "Samwel", 18);
	LOG(INFO, "Hello My Name is {0}, {1} and I'm {{{2}}}.", "Youssef", "Samwel", 18);

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