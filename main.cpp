#include "CppUtility.hpp"
#include <thread>
#include <chrono>
#include <windows.h>

void test() {
	LOG(INFO, "{0} + {1} = {2}", 10, 5, 10 + 5, GetCurrentThreadId());
	LOG(INFOBOLD, "{0} + {1} = {2}", 10, 5, 10 + 5, GetCurrentThreadId());
	std::this_thread::sleep_for(std::chrono::seconds(2));
	LOG(WARNING, "{0} + {1} = {2}", 10, 5, 10 + 5, GetCurrentThreadId());
	LOG(ERR, "{0} + {1} = {2}", 10, 5, 10 + 5, GetCurrentThreadId());
}

int main() {
	ut::Logger::GlobalLoggerOptions.IncludeDate = true;
	ut::Logger::GlobalLoggerOptions.IncludeFileAndLine = false;
	for (int i = 0; i < 5; i++) {
		std::thread x(test);
		x.detach();
	}
	int x;
	std::cin >> x;
}