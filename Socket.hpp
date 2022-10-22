#pragma once

// Code style inspired by Nothings STB
// Define SOCKET_API_IMPLEMENTATION in one of your CPP files

#include <string>
#include <cstdint>
#include <vector>
#include <ostream>
#ifdef SOCKET_API_IMPLEMENTATION
#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <cstring>
#else
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif
#include <iostream>
#include <sstream>
#include <cassert>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
typedef int socklen_t;
#endif
#endif

namespace sw {

	// Calls WSAStartup on windows
	bool Startup();
	// Calls WSACleanup on windows
	void CleanUp();

	struct SockError {
		int nErrorCode;
		std::string sErrorString;
	};

	SockError GetLastError();

	enum class SocketType
	{
		TCP,
		UDP,
		RAW
	};

	enum class SocketInterface {
		// 127.*.*.* packets only from your computer
		Loopback,
		// Binds to all interfaces best option for server
		Any,
		// You enter interface address in bind function
		// ex: 127.0.0.1, 192.168.1.50
		CustomInterface
	};

	struct Endpoint {
		std::string mAddress;
		uint16_t mPort = 0;

		Endpoint() = default;
		Endpoint(uint16_t Port) {
			mAddress = "0.0.0.0";
			mPort = Port;
		}
		Endpoint(const std::string& Address, uint16_t Port) {
			mAddress = Address;
			mPort = Port;
		}

		/// <summary>
		/// Performs DNS look up
		/// </summary>
		/// <param name="domain">The domain without protocol (http://) and without and / must www.example.com</param>
		/// <param name="ServicesName">The protocol (http, https, etc.)</param>
		/// <returns>If string is empty then the function failed.</returns>
		static std::string GetDomainAddress(const std::string& domain, const char* ServicesName = nullptr);

		static Endpoint GetEndPoint(const std::string& address, uint16_t port) {
			return { address, port };
		}

		static Endpoint GetEndPointBroadcast(uint16_t port);

		friend std::ostream& operator<<(std::ostream& stream, const Endpoint& endpoint) {
			stream << endpoint.mAddress << ":" << endpoint.mPort;
			return stream;
		}
	};

	class Socket
	{

	public:
		Socket() = default;
		Socket(uint64_t RawSocketHandle, SocketType type, const Endpoint& Endpoint, bool IsConnected) :
			mSocket(RawSocketHandle), mType(type), mEndpoint(Endpoint), mIsConnected(IsConnected) {}
		Socket(SocketType type);
		Socket(Socket& copy) = delete;
		Socket(Socket&&) noexcept;
		Socket& operator=(Socket&&) noexcept;
		~Socket();
		/// <summary>
		/// For more information on SocketInterface go to the enum class definition.
		/// On failure throws exception
		/// </summary>
		/// <param name="port"></param>
		/// <param name="interfaceType"></param>
		/// <returns></returns>
		Socket& Bind(SocketInterface interfaceType, uint16_t port = 0, const char* customInterface = nullptr);

		/// <summary>
		/// On failure throws exception
		/// </summary>
		/// <param name="nMaxBacklog"></param>
		/// <returns></returns>
		Socket& Listen(int nMaxBacklog);
		Socket& Connect(const std::string& address, uint16_t port);

		int32_t Send(const char* str);
		int32_t Send(const std::string& str);
		int32_t Send(const void* pData, int32_t size);
		int32_t SendTo(const void* pData, int32_t size, const std::string& DetinationIP, uint16_t DestinationPort);
		int32_t SendTo(const void* pData, int32_t size, const Endpoint& Destination);

		// If in nonblocking mode pRecvBytes will be -1 until the os recieves the data.
		// WaitAll and Peek cannot be used together and WaitAll cannot be used with nonblocking sockets
		int32_t Recv(const void* pOutData, int32_t size, bool WaitAll, bool Peek = false);
		// WaitAll and Peek cannot be used together and WaitAll cannot be used with nonblocking sockets
		std::string RecvString(int32_t size, bool WaitAll, bool Peek = false);
		// sourceIP is your ip address
		int32_t RecvFrom(const void* pData, int32_t size, Endpoint* PacketSource = nullptr);

		/// <summary>
		/// Changes blocking mode, if the blocking mode is the same then it does nothing.
		/// </summary>
		/// <param name="blocking"></param>
		/// <returns></returns>
		Socket& SetBlockingMode(bool blocking);

		/// <summary>
		/// Accepts connection for TCP socket
		/// </summary>
		/// <returns>Check the IsConnected flag to determine if this is a valid connection.</returns>
		Socket Accept();

		const Endpoint& GetEndpoint();

		// Proper Disconnection.
		Socket& Disconnect();

		/// <summary>
		/// Nagle algorithim waits until the Send() packets are large enough before actually sending them.
		/// Therefore potentially increasing latency.
		/// By default it is enabled.
		/// </summary>
		/// <param name="State">True/False => Enable/Disable</param>
		void SetNagleAlgorthim(bool State);

		/// <summary>
		/// Sends TCP Packets (does not affect client/server application)
		/// to check connection state (in case the application didn't have a proper disconnection)
		/// </summary>
		/// <param name="State">Enable/Disable</param>
		void SetTCPKeepAliveOption(bool State, uint8_t KeepAliveProbeCount);

		/// <summary>
		/// When Accept() is called an error could occur or when using nonblocking socket an error will occur;
		/// this function tells you if this socket is valid.
		/// </summary>
		/// <returns>Socket Validatity</returns>
		bool IsValid();

		Socket& EnableBroadcast();

		void WaitForData();
		static void WaitForData(const std::vector<sw::Socket>& Connections);

		inline bool IsBlocking() {
			return mIsBlocking;
		}

		bool IsConnected();

	private:
		bool mIsConnected = false;
		uint64_t mSocket = 0;
		SocketType mType = SocketType::TCP;
		Endpoint mEndpoint = { "0.0.0.0", 0 };
		bool mIsBlocking = true;
		bool mKeepAlive = false;
	};

#ifdef SOCKET_API_IMPLEMENTATION
	bool Startup() {
#ifdef _WIN32
		WSADATA ws;
		return 0 == WSAStartup(MAKEWORD(2, 2), &ws);
#endif
		return true;
	}

	void CleanUp() {
#ifdef _WIN32
		WSACleanup();
#endif
	}

	SockError GetLastError() {
		SockError error;
#ifndef _WIN32
		error.nErrorCode = errno;
		error.sErrorString = strerror(error.nErrorCode);
#else
		int errorCode = WSAGetLastError();
		char* s = NULL;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, WSAGetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&s, 0, NULL);
		fprintf(stderr, "%s\n", s);
		error.nErrorCode = errorCode;
		error.sErrorString = s;
#endif
		return error;
	}

	bool GetSocketConnectionStateFromError() {
#ifdef _WIN32
		int error = WSAGetLastError();
		return (error == WSAEWOULDBLOCK) || (error == WSAEOPNOTSUPP);
#else
#error "Not supported"
#endif
	}

	static void Socket_ThrowException(bool invalidArgs = false, const char* detailedError = nullptr)
	{
		std::stringstream ss;
		if (!invalidArgs)
		{
			auto error = GetLastError();
			ss << "Error Code: " << error.nErrorCode << ", Error String: " << error.sErrorString;
		}
		else
		{
			if (detailedError)
			{
				ss << detailedError;
			}
			else
			{
				ss << "Invalid Arguments";
			}
		}
		throw std::runtime_error(ss.str());
	}

	Socket::Socket(SocketType type)
	{
#ifdef _WIN32
		if (type == SocketType::RAW)
		{
			Socket_ThrowException(true, "Raw Sockets on windows not implemented. RAW Socket on Windows Need WinPcap");
		}
#endif
		int domain = AF_INET;
		int typeInt{};
		int ipproto{};
		switch (type)
		{
		case SocketType::TCP:
			ipproto = IPPROTO_TCP;
			typeInt = SOCK_STREAM;
			break;
		case SocketType::UDP:
			ipproto = IPPROTO_UDP;
			typeInt = SOCK_DGRAM;
			break;
		case SocketType::RAW:
			// domain = AF_PACKET;
			// ipproto = htons(ETH_P_ALL);
			typeInt = SOCK_RAW;
			break;
		default:
			Socket_ThrowException(true);
		}
		mSocket = ::socket(domain, typeInt, ipproto);
		mType = type;
		mEndpoint.mPort = 0;
		mEndpoint.mAddress = "0.0.0.0";
		if (mSocket < 0)
			Socket_ThrowException();
	}

	Socket::Socket(Socket&& move) noexcept
	{
		this->~Socket();
		memcpy(this, &move, sizeof(Socket));
		memset(&move, 0, sizeof(Socket));
	}

	Socket& Socket::operator=(Socket&& move) noexcept
	{
		this->~Socket();
		memcpy(this, &move, sizeof(Socket));
		memset(&move, 0, sizeof(Socket));
		return *this;
	}

	Socket::~Socket()
	{
		if (mSocket <= 0) return;
		Disconnect();
#ifdef _WIN32
		::closesocket(mSocket);
#else
		::close(mSocket);
#endif
	}

	static ::in_addr GetIPAddress(bool adapaterAddressFlag, bool subnetAddressFlag, bool broadcastAddressFlag, int* pOutSubnetBits = nullptr)
	{
		static ::in_addr adapterAddress;
		static ::in_addr subnetAddress;
		static ::in_addr broadcastAddress;
		static int subnetBits;
		static bool initalize = true;
		if (initalize)
		{
			initalize = false;
#ifdef _WIN32
			ULONG size = 0;
			GetAdaptersInfo(nullptr, &size);
			PIP_ADAPTER_INFO ip = (PIP_ADAPTER_INFO)malloc(size);
			void* allocationAddress = ip;
			GetAdaptersInfo(ip, &size);
			while (true)
			{
				if (ip->Type & (IF_TYPE_IEEE80211 | MIB_IF_TYPE_ETHERNET))
					if (strcmp(ip->IpAddressList.IpAddress.String, "0.0.0.0") != 0 &&
						strcmp(ip->GatewayList.IpAddress.String, "0.0.0.0") != 0 &&
						strcmp(ip->DhcpServer.IpAddress.String, "0.0.0.0") != 0)
					{
						break;
					}
				ip = ip->Next;
				if (!ip)
					break;
			}
			if (ip != NULL)
			{
				uint32_t adapterAddressInt = inet_addr(ip->IpAddressList.IpAddress.String);
				uint32_t subnetAddressInt = inet_addr(ip->IpAddressList.IpMask.String);
				subnetBits =
					(((subnetAddressInt >> 24) == 0x00) ? 8 : 0) +
					(((subnetAddressInt >> 16) == 0x00) ? 8 : 0) +
					(((subnetAddressInt >> 8) == 0x00) ? 8 : 0) +
					(((subnetAddressInt >> 0) == 0x00) ? 8 : 0);
				unsigned char broadcastAddressInt[4];
				broadcastAddressInt[3] = subnetBits >= 8 ? 255 : (adapterAddressInt >> 24) & 0xff;
				broadcastAddressInt[2] = subnetBits >= 16 ? 255 : (adapterAddressInt >> 16) & 0xff;
				broadcastAddressInt[1] = subnetBits >= 24 ? 255 : (adapterAddressInt >> 8) & 0xff;
				broadcastAddressInt[0] = subnetBits >= 32 ? 255 : (adapterAddressInt >> 0) & 0xff;
				memcpy(&adapterAddress, &adapterAddressInt, sizeof(uint32_t));
				memcpy(&subnetAddress, &subnetAddressInt, sizeof(uint32_t));
				memcpy(&broadcastAddress, &broadcastAddressInt, sizeof(uint32_t));
			}
			free(allocationAddress);
#else
			// from https://stackoverflow.com/questions/18100761/obtaining-subnetmask-in-c
			::ifaddrs* ifap;
			::getifaddrs(&ifap);
			for (::ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr->sa_family == AF_INET)
				{
					std::string address = inet_ntoa(((sockaddr_in*)ifa->ifa_addr)->sin_addr);
					std::string netmask = inet_ntoa(((sockaddr_in*)ifa->ifa_netmask)->sin_addr);
					if (strcmp(address.c_str(), "127.0.0.1") != 0 && strcmp(address.c_str(), "0.0.0.0") != 0)
					{
						uint32_t adapterAddressInt = ((::sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
						uint32_t subnetAddressInt = ((::sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr;
						subnetBits =
							(((subnetAddressInt >> 24) == 0x00) ? 8 : 0) +
							(((subnetAddressInt >> 16) == 0x00) ? 8 : 0) +
							(((subnetAddressInt >> 8) == 0x00) ? 8 : 0) +
							(((subnetAddressInt >> 0) == 0x00) ? 8 : 0);
						unsigned char broadcastAddressInt[4];
						broadcastAddressInt[3] = subnetBits >= 8 ? 255 : (adapterAddressInt >> 24) & 0xff;
						broadcastAddressInt[2] = subnetBits >= 16 ? 255 : (adapterAddressInt >> 16) & 0xff;
						broadcastAddressInt[1] = subnetBits >= 24 ? 255 : (adapterAddressInt >> 8) & 0xff;
						broadcastAddressInt[0] = subnetBits >= 32 ? 255 : (adapterAddressInt >> 0) & 0xff;
						memcpy(&adapterAddress, &adapterAddressInt, sizeof(uint32_t));
						memcpy(&subnetAddress, &subnetAddressInt, sizeof(uint32_t));
						memcpy(&broadcastAddress, &broadcastAddressInt, sizeof(uint32_t));
						break;
					}
				}
			}
			::freeifaddrs(ifap);
#endif
		}
		if (pOutSubnetBits)
			*pOutSubnetBits = subnetBits;
		if (adapaterAddressFlag)
		{
			return adapterAddress;
		}
		if (subnetAddressFlag)
		{
			return subnetAddress;
		}
		if (broadcastAddressFlag)
		{
			return broadcastAddress;
		}
		return adapterAddress;
	}

	// Throws Exception on failure
	Socket& Socket::Bind(SocketInterface interfaceType, uint16_t port, const char* customInterface)
	{
		sockaddr_in addr{};
		switch (interfaceType)
		{
		case SocketInterface::Loopback:
			addr.sin_addr.s_addr = INADDR_LOOPBACK;
			break;
		case SocketInterface::Any:
			addr.sin_addr.s_addr = INADDR_ANY;
			break;
		case SocketInterface::CustomInterface:
			addr.sin_addr.s_addr = inet_addr(customInterface);
			break;
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		mEndpoint.mPort = port;
		if (::bind(mSocket, (sockaddr*)&addr, sizeof(addr)) < 0)
		{
			Socket_ThrowException();
		}
		if (port == 0) {
			sockaddr_in sin{};
			int len = sizeof(sockaddr_in);
			getsockname(mSocket, (sockaddr*)&sin, &len);
			mEndpoint.mPort = ntohs(sin.sin_port);
		}
		return *this;
	}

	Socket& Socket::Listen(int nMaxBacklog)
	{
		assert(mType == SocketType::TCP && "Must be TCP Socket to use Listen Function()");
		if (::listen(mSocket, nMaxBacklog) < 0)
			Socket_ThrowException();
		return *this;
	}

	Socket& Socket::Connect(const std::string& address, uint16_t port)
	{
		sockaddr_in addr{};
		addr.sin_addr.s_addr = inet_addr(address.c_str());
		addr.sin_port = htons(port);
		addr.sin_family = AF_INET;
		if (::connect(mSocket, (sockaddr*)&addr, sizeof(addr)) < 0)
		{
			mIsConnected = GetSocketConnectionStateFromError();
		}
		return *this;
	}

	int32_t Socket::Send(const char* str)
	{
		return Send(str, (int32_t)strlen(str));
	}

	int32_t Socket::Send(const std::string& str)
	{
		return Send(str.c_str(), (int)str.size());
	}

	int32_t Socket::Send(const void* pData, int32_t size)
	{
		if (size == 0) return 0;
		assert(mType == SocketType::TCP && "Must be TCP Socket to use Send Function()");
		int32_t readBytes = ::send(mSocket, (const char*)pData, size, 0);
		if (readBytes == 0) mIsConnected = false;
		if (readBytes < 0)
			mIsConnected = GetSocketConnectionStateFromError();
		return readBytes;
	}

	int32_t Socket::SendTo(const void* pData, int32_t size, const std::string& destIP, uint16_t destPort)
	{
		sockaddr_in dest{};
		dest.sin_addr.s_addr = inet_addr(destIP.c_str());
		dest.sin_family = AF_INET;
		dest.sin_port = htons(destPort);
		socklen_t len = sizeof(dest);
		int sentBytes = ::sendto(mSocket, (const char*)pData, size, 0, (sockaddr*)&dest, len);
		return sentBytes;
	}

	int32_t Socket::SendTo(const void* pData, int32_t size, const Endpoint& endpoint)
	{
		assert(mType != SocketType::TCP && "Must be UDP/RAW Socket to use Send Function()");
		u_long broadcastEnable = 1;
		::setsockopt(mSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&broadcastEnable, sizeof(broadcastEnable));
		sockaddr_in dest{};
		dest.sin_addr.s_addr = inet_addr(endpoint.mAddress.c_str());
		dest.sin_family = AF_INET;
		dest.sin_port = htons(endpoint.mPort);
		socklen_t len = sizeof(dest);
		int32_t sentBytes = ::sendto(mSocket, (const char*)pData, size, 0, (sockaddr*)&dest, len);
		return sentBytes;
	}

	int32_t Socket::Recv(const void* pOutData, int32_t size, bool WaitAll, bool Peek)
	{
		assert(mType == SocketType::TCP && "Must be TCP Socket to use Recv Function()");
		if (WaitAll && !mIsBlocking)
			throw std::runtime_error("Cannot use WaitAll with Non-Blocking sockets.");

		if (WaitAll && Peek)
			throw std::runtime_error("Cannot use WaitAll and Peek at the same time.");

		int flags = (Peek ? MSG_PEEK : 0) | (WaitAll ? MSG_WAITALL : 0);
		int32_t recvBytes = ::recv(mSocket, (char*)pOutData, size, flags);
		if (recvBytes == 0) {
			mIsConnected = false;
			return 0;
		}
		if (recvBytes < 0)
		{
			mIsConnected = GetSocketConnectionStateFromError();
			return 0;
		}
		return recvBytes;
	}

	std::string Socket::RecvString(int32_t size, bool WaitAll, bool Peek)
	{
		std::string str;
		str.resize(size);
		auto bytes = Recv(str.data(), size, WaitAll, Peek);
		str.resize(bytes <= 0 ? 0 : bytes);
		return str;
	}

	int32_t Socket::RecvFrom(const void* pData, int32_t size, Endpoint* PacketSource)
	{
		assert(mType != SocketType::TCP && "Must be UDP/RAW Socket to use RecvFrom Function()");
		sockaddr_in src{};
		socklen_t len = sizeof(src);
		int recvBytes = ::recvfrom(mSocket, (char*)pData, size, 0, (sockaddr*)&src, &len);
		if (PacketSource)
		{
			PacketSource->mAddress = inet_ntoa(src.sin_addr);
			PacketSource->mPort = ntohs(src.sin_port);
		}
		return recvBytes;
	}

	Socket& Socket::SetBlockingMode(bool blocking)
	{
		if (mIsBlocking == blocking)
			return *this;
		assert(mType != SocketType::RAW && "Cannot set blocking mode on RAW Socket");
		u_long code = blocking ? 0 : 1;
#ifdef _WIN32
		if (::ioctlsocket(mSocket, FIONBIO, &code) < 0)
			Socket_ThrowException();
#else
		if (::ioctl(mSocket, FIONBIO, &code) < 0)
			Socket_ThrowException();
#endif
		mIsBlocking = blocking;
		return *this;
	}

	Socket Socket::Accept()
	{
		assert(mType == SocketType::TCP && "Must be TCP Socket to use Accept Function()");
		sockaddr_in addrs{};
		socklen_t len = sizeof(sockaddr_in);
		uint64_t client = (uint64_t)::accept(mSocket, (sockaddr*)&addrs, &len);
		if (client <= 0)
		{
			return Socket(0, sw::SocketType::TCP, { "0.0.0.0", 0 }, false);
		}
		return Socket(client, SocketType::TCP, { inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port) }, true);
	}

	const Endpoint& Socket::GetEndpoint()
	{
		return mEndpoint;
	}

	// Proper Disconnection.
	Socket& Socket::Disconnect()
	{
#ifdef _WIN32
		::shutdown(mSocket, SD_BOTH);
#else
		::shutdown(mSocket, SHUT_RDWR);
#endif
		return *this;
	}

	void Socket::SetNagleAlgorthim(bool State)
	{
		uint32_t state = State ? 1 : 0;
		::setsockopt(mSocket, SOL_SOCKET, TCP_NODELAY, (const char*)&state, sizeof(uint32_t));
	}

	void Socket::SetTCPKeepAliveOption(bool State, uint8_t KeepAliveProbeCount)
	{
		uint32_t state = State ? 1 : 0;
		::setsockopt(mSocket, SOL_SOCKET, SO_KEEPALIVE, (const char*)&state, sizeof(uint32_t));
		uint32_t propeCount = KeepAliveProbeCount;
		::setsockopt(mSocket, IPPROTO_TCP, TCP_KEEPCNT, (const char*)&propeCount, sizeof(uint32_t));
		mKeepAlive = State;
	}

	bool Socket::IsValid()
	{
		return mSocket > 0;
	}

	void Socket::WaitForData()
	{
		WSAPOLLFD fdArray{};
		fdArray.fd = mSocket;
		fdArray.events = POLLRDNORM;
		::WSAPoll(&fdArray, 1, INFINITE);
	}

	void Socket::WaitForData(const std::vector<sw::Socket>& Connections)
	{
		if (Connections.size() == 0)
			return;
#ifdef _WIN32
		WSAPOLLFD* fdArray = (WSAPOLLFD*)_malloca(sizeof(WSAPOLLFD) * Connections.size());
		if (!fdArray)
			return;
		for (int i = 0; i < Connections.size(); i++) {
			fdArray[i].fd = Connections[i].mSocket;
			fdArray[i].events = POLLRDNORM;
		}
		::WSAPoll(fdArray, (ULONG)Connections.size(), INFINITE);
#else
#error "Not supported"
#endif
		_freea(fdArray);
	}

	bool Socket::IsConnected()
	{
		assert(mType == SocketType::TCP);
		return mIsConnected;
	}

	std::string Endpoint::GetDomainAddress(const std::string& domain, const char* ServicesName)
	{
		ADDRINFOA hints{};
		PADDRINFOA result{};
		hints.ai_family = AF_INET;
		getaddrinfo(domain.c_str(), ServicesName, &hints, &result);
		if (!result)
			return std::string();
		return inet_ntoa(((sockaddr_in*)result->ai_addr)->sin_addr);
	}

	Endpoint Endpoint::GetEndPointBroadcast(uint16_t port)
	{
		Endpoint ep;
		ep.mAddress = inet_ntoa(GetIPAddress(false, false, true));
		ep.mPort = port;
		return ep;
	}

	Socket& Socket::EnableBroadcast()
	{
		int enabled = 1;
		setsockopt(mSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&enabled, sizeof(enabled));
		return *this;
	}

#endif

}
