#pragma once

// Code style inspired by Nothings STB
// Define SOCKET_API_IMPLEMENTATION in one of your CPP files
// #define SOCKET_API_IMPLEMENTATION
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <string>
#include <cstdint>
#include <vector>
#include <ostream>
#include <memory>
#include <sstream>
#ifdef SOCKET_API_IMPLEMENTATION
#ifndef TCP_KEEPCNT
#define	TCP_KEEPCNT	1024
#endif
#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <cstring>
#else
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

	enum NetworkAdapterTypeFlags : uint32_t {
		NETWORK_ADAPTER_LOOPBACK = 0b0001,
		NETWORK_ADAPTER_ETHERNET = 0b0010,
		NETWORK_ADAPTER_IEEE801Wireless = 0b0100,
		NETWORK_ADAPTER_OtherOrUnknown = 0b1000
	};

	struct NetworkAdapter {
		uint32_t TypeFlags = 0;
		std::string Name;
		std::string Description;
		// If adapter interface is "0.0.0.0" then the adapter is offline
		std::vector<std::string> IPv4Address;
		std::vector<std::string> SubnetAddress;
		std::vector<std::string> BroadcastAddress;
		std::string GatewayAddress;

		operator std::string() {
			std::stringstream ss;
			auto flagSet = [](uint32_t test, uint32_t input) {
				return (input & test) ? "true" : "false";
				};
			auto ipToArrayString = [](const std::vector<std::string>& source) {
				std::stringstream ss;
				ss << "[";
				for (size_t i = 0; i < source.size(); i++) {
					ss << '"' << source[i] << '"';
					if (i != source.size() - 1)
						ss << ", ";
				}
				ss << "]";
				return ss.str();
				};
			ss << "\"Name\": \"" << Name << "\",\n\"Description\": \"" << Description << "\",\n\"Data\": { \n\t\"IPv4\": " << ipToArrayString(IPv4Address)
				<< ",\n\t\"Subnet\": " << ipToArrayString(SubnetAddress)
				<< ",\n\t\"Broadcast\": " << ipToArrayString(BroadcastAddress)
				<< ",\n\t\"Gateway\": \"" << GatewayAddress << "\"\n}\n"
				<< "\"Type\": {\n\t\"Loopback\": " << flagSet(NETWORK_ADAPTER_LOOPBACK, TypeFlags)
				<< ",\n\t\"Ethernet\": " << flagSet(NETWORK_ADAPTER_ETHERNET, TypeFlags)
				<< ",\n\t\"IEEE801Wireless\": " << flagSet(NETWORK_ADAPTER_IEEE801Wireless, TypeFlags)
				<< ",\n\t\"OtherOrUnknown\": " << flagSet(NETWORK_ADAPTER_OtherOrUnknown, TypeFlags)
				<< "\n}";
			return ss.str();
		}
	};

	// Calls WSAStartup on windows
	bool Startup();
	// Calls WSACleanup on windows
	void CleanUp();

    uint16_t HostToNetworkOrder(uint16_t hostValue);
    uint32_t HostToNetworkOrder(uint32_t hostValue);

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
		std::string Address;
		uint16_t Port = 0;

		Endpoint() = default;
		explicit Endpoint(uint16_t Port) {
			Address = "0.0.0.0";
			this->Port = Port;
		}
		Endpoint(const std::string& Address, uint16_t Port) {
			this->Address = Address;
			this->Port = Port;
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

		[[nodiscard]] std::string ToString() const {
			return Address + ":" + std::to_string(Port);
		}

		explicit operator std::string() const {
			return ToString();
		}

		friend std::ostream& operator<<(std::ostream& stream, const Endpoint& endpoint) {
			stream << endpoint.ToString();
			return stream;
		}
	};

	class Socket
	{

	public:
		Socket() = default;
		Socket(uint64_t RawSocketHandle, SocketType type, const Endpoint& Endpoint, bool IsConnected) :
			mSocket(RawSocketHandle), mType(type), mEndpoint(Endpoint) {
			if (IsConnected) mConnectedTimestamp = time(NULL);
		}
		Socket(SocketType type);
		Socket(Socket& copy) = default;
		Socket(Socket&&) noexcept;
		Socket& operator=(Socket&&) noexcept;
        Socket& operator=(const Socket&) = default;
		~Socket() noexcept;
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

		/// <summary>
		/// Joins multicast group
		/// The multicast addresses are in the range 224.0.0.0 through 239.255.255.255.
		/// From iana.org
		/// This function must be called after Bind(...).
		/// This function tells the kernel to listen packets from this group and send them
		/// to your application.
		/// NOTE: Throws exception on failure.
		/// </summary>
		Socket& JoinMulticastGroup(const std::string& GroupAddress);

		const Endpoint& GetEndpoint();

		// Proper Disconnection.
		Socket& Disconnect();

        void Close();

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

		Socket& SetBroadcastOption(bool value);

		// Allows other applications to use this interface(ex loopback, any, etc...) and port combination.
		// Must be called before Bind() or will not be effective.
		Socket& SetReuseAddrOption(bool value);

		// True means your application recv your multicast packets
		Socket& SetMulticastLoopOption(bool value);

		/// <summary>
		/// Timeout is in milliseconds
		/// </summary>
		/// <param name="Connections"></param>
		bool WaitForData(int32_t timeout);
		static void WaitForData(const std::vector<sw::Socket>& Connections, int32_t timeout);
		static void WaitForData(const std::vector<std::unique_ptr<sw::Socket>>& Connections, int32_t timeout);
		static void WaitForData(const std::vector<std::shared_ptr<sw::Socket>>& Connections, int32_t timeout);
		static std::vector<NetworkAdapter> EnumerateNetworkAdapters();

		[[nodiscard]] bool IsBlocking() const {
			return mIsBlocking;
		}

		[[nodiscard]] bool PollSocketData() { return WaitForData(0); }

		bool IsConnected() const;

		constexpr uint64_t SockFd() const { return mSocket; }
		// time(NULL) when connection was established
		constexpr uint64_t ConnectedTimestamp() const { return mConnectedTimestamp; }

	private:
		uint64_t mSocket = 0;
		SocketType mType = SocketType::TCP;
		Endpoint mEndpoint = { "0.0.0.0", 0 };
		bool mIsBlocking = true;
		bool mKeepAlive = false;
		uint64_t mConnectedTimestamp = 0;
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

    uint16_t HostToNetworkOrder(uint16_t hostValue)
    {
        return htons(hostValue);
    }

    uint32_t HostToNetworkOrder(uint32_t hostValue)
    {
        return htonl(hostValue);
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
		mEndpoint.Port = 0;
		mEndpoint.Address = "0.0.0.0";
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

	Socket::~Socket() noexcept
	{
#if 0
		if (IsValid()) {
			Disconnect();
#ifdef _WIN32
			::closesocket(mSocket);
#else
			::close(mSocket);
#endif
		}
#endif
	}

	bool Socket::IsConnected() const {
		pollfd query = {};
		query.fd = mSocket;
		query.events = POLLRDNORM;
#ifdef _WIN32
		if (WSAPoll(&query, 1, 0) == SOCKET_ERROR) {
#else
		if (poll(&query, 1, 0) == -1) {
#endif
			return false;
		}
		if (query.revents & POLLHUP) {
			return false;
		}
		return true;
	}

	// Throws Exception on failure
	Socket& Socket::Bind(SocketInterface interfaceType, uint16_t port, const char* customInterface)
	{
		sockaddr_in addr{};
		switch (interfaceType)
		{
		case SocketInterface::Loopback:
			addr.sin_addr.s_addr = inet_addr("127.0.0.1");
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
		mEndpoint.Port = port;
		if (::bind(mSocket, (sockaddr*)&addr, sizeof(addr)) < 0)
		{
			Socket_ThrowException();
		}
		if (port == 0) {
			sockaddr_in sin{};
			socklen_t len = sizeof(sockaddr_in);
			getsockname(mSocket, (sockaddr*)&sin, &len);
			mEndpoint.Address = inet_ntoa(sin.sin_addr);
			mEndpoint.Port = ntohs(sin.sin_port);
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
		if (::connect(mSocket, (sockaddr*)&addr, sizeof(addr)) == 0)
		{
			mConnectedTimestamp = time(NULL);
		}
		else {
			mConnectedTimestamp = 0;
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
		dest.sin_addr.s_addr = inet_addr(endpoint.Address.c_str());
		dest.sin_family = AF_INET;
		dest.sin_port = htons(endpoint.Port);
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
			return 0;
		}
		if (recvBytes < 0)
		{
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
			PacketSource->Address = inet_ntoa(src.sin_addr);
			PacketSource->Port = ntohs(src.sin_port);
		}
		return recvBytes;
	}

	Socket& Socket::SetBlockingMode(bool blocking)
	{
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
		if (client == UINT64_MAX)
		{
			return Socket(0, sw::SocketType::TCP, { "0.0.0.0", 0 }, false);
		}
		auto conn = Socket(client, SocketType::TCP, { inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port) }, true);
		conn.mIsBlocking = mIsBlocking;
		return conn;
	}

	const Endpoint& Socket::GetEndpoint()
	{
		return mEndpoint;
	}

	// Proper Disconnection.
	Socket& Socket::Disconnect()
	{
		if(IsValid()) {
#ifdef _WIN32
			::shutdown(mSocket, SD_BOTH);
#else
			::shutdown(mSocket, SHUT_RDWR);
#endif
		}
		return *this;
	}

    void Socket::Close() {
 #ifdef _WIN32
			::closesocket(mSocket);
#else
			::close(mSocket);
#endif
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
		return (mSocket > 0) && (mSocket != -1);
	}

	bool Socket::WaitForData(int32_t timeout)
	{
		pollfd fdArray{};
		fdArray.fd = mSocket;
		fdArray.events = POLLRDNORM;
#ifdef _WIN32
		::WSAPoll(&fdArray, 1, timeout);
#else
		poll(&fdArray, 1, timeout);
#endif
		return fdArray.revents & POLLRDNORM;
	}

	void Socket::WaitForData(const std::vector<sw::Socket>& Connections, int32_t timeout)
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
		::WSAPoll(fdArray, (uint32_t)Connections.size(), timeout);
		_freea(fdArray);

#else
		pollfd* fdArray = (pollfd*)malloc(sizeof(pollfd) * Connections.size());
		if (!fdArray)
			return;
		for (int i = 0; i < Connections.size(); i++) {
			fdArray[i].fd = Connections[i].mSocket;
			fdArray[i].events = POLLRDNORM;
		}
		poll(fdArray, (uint32_t)Connections.size(), timeout);
		free(fdArray);
#endif
	}

	void Socket::WaitForData(const std::vector<std::unique_ptr<sw::Socket>>& Connections, int32_t timeout)
	{
		if (Connections.size() == 0)
			return;
#ifdef _WIN32
		WSAPOLLFD* fdArray = (WSAPOLLFD*)_malloca(sizeof(WSAPOLLFD) * Connections.size());
		if (!fdArray)
			return;
		for (int i = 0; i < Connections.size(); i++) {
			fdArray[i].fd = Connections[i]->SockFd();
			fdArray[i].events = POLLRDNORM;
		}
		::WSAPoll(fdArray, (uint32_t)Connections.size(), timeout);
		_freea(fdArray);
#else
		pollfd* fdArray = (pollfd*)malloc(sizeof(pollfd) * Connections.size());
		if (!fdArray)
			return;
		for (int i = 0; i < Connections.size(); i++) {
			fdArray[i].fd = Connections[i]->SockFd();
			fdArray[i].events = POLLRDNORM;
		}
		poll(fdArray, (uint32_t)Connections.size(), timeout);
		free(fdArray);
#endif
	}

	void Socket::WaitForData(const std::vector<std::shared_ptr<sw::Socket>>& Connections, int32_t timeout)
	{
		if (Connections.size() == 0)
			return;
#ifdef _WIN32
		WSAPOLLFD* fdArray = (WSAPOLLFD*)_malloca(sizeof(WSAPOLLFD) * Connections.size());
		if (!fdArray)
			return;
		for (int i = 0; i < Connections.size(); i++) {
			fdArray[i].fd = Connections[i]->SockFd();
			fdArray[i].events = POLLRDNORM;
		}
		::WSAPoll(fdArray, (ULONG)Connections.size(), timeout);
		_freea(fdArray);
#else
		pollfd* fdArray = (pollfd*)malloc(sizeof(pollfd) * Connections.size());
		if (!fdArray)
			return;
		for (int i = 0; i < Connections.size(); i++) {
			fdArray[i].fd = Connections[i]->SockFd();
			fdArray[i].events = POLLRDNORM;
		}
		poll(fdArray, (uint32_t)Connections.size(), timeout);
		free(fdArray);
#endif
		
	}

	std::string Endpoint::GetDomainAddress(const std::string& domain, const char* ServicesName)
	{
		addrinfo hints{};
    	addrinfo* result{};
		hints.ai_family = AF_INET;
		getaddrinfo(domain.c_str(), ServicesName, &hints, &result);
		if (!result)
			return std::string();
		return inet_ntoa(((sockaddr_in*)result->ai_addr)->sin_addr);
	}

	Socket& Socket::SetBroadcastOption(bool value)
	{
		int enabled = value ? 1 : 0;
		setsockopt(mSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&enabled, sizeof(enabled));
		return *this;
	}

	std::vector<NetworkAdapter> Socket::EnumerateNetworkAdapters()
	{
		std::vector<NetworkAdapter> result;
#ifdef _WIN32
		ULONG adapterInfoSize = 0;
		GetAdaptersInfo(nullptr, &adapterInfoSize);
		IP_ADAPTER_INFO* adapterInfo = (IP_ADAPTER_INFO*)new char[adapterInfoSize];
		GetAdaptersInfo(adapterInfo, &adapterInfoSize);
		while (adapterInfo->Next) {
			NetworkAdapter na;
			na.Name = adapterInfo->AdapterName;
			na.Description = adapterInfo->Description;
			PIP_ADDR_STRING ipAddrs = &adapterInfo->IpAddressList;
			while (ipAddrs) {
				std::string ip = ipAddrs->IpAddress.String;
				std::string mask = ipAddrs->IpMask.String;

				auto extractIpFromString = [](const std::string ip, uint8_t output[4]) {
					size_t ip_d0 = ip.find(".", 0);
					size_t ip_d1 = ip.find(".", ip_d0 + 1);
					size_t ip_d2 = ip.find(".", ip_d1 + 1);

					output[0] = uint8_t(std::stoul(ip.substr(0, ip_d0)));
					output[1] = uint8_t(std::stoul(ip.substr(ip_d0 + 1, ip_d1 - ip_d0 - 1)));
					output[2] = uint8_t(std::stoul(ip.substr(ip_d1 + 1, ip_d2 - ip_d1 - 1)));
					output[3] = uint8_t(std::stoul(ip.substr(ip_d2 + 1)));
					};
				uint8_t ip8[4];
				uint8_t mask8[4];
				extractIpFromString(mask, mask8);
				extractIpFromString(ip, ip8);
				std::string broadcastIp;
				for (int i = 0; i < 4; i++) {
					mask8[i] = mask8[i] ^ 0xFF;
					broadcastIp += std::to_string(ip8[i] | mask8[i]);
					if (i != 3)
						broadcastIp += ".";
				}
				na.IPv4Address.push_back(std::move(ip));
				na.SubnetAddress.push_back(std::move(mask));
				na.BroadcastAddress.push_back(broadcastIp);
				ipAddrs = ipAddrs->Next;
			}
			na.GatewayAddress = adapterInfo->GatewayList.IpAddress.String;
			auto type = adapterInfo->Type;
			if (type & MIB_IF_TYPE_ETHERNET) {
				na.TypeFlags = na.TypeFlags | NETWORK_ADAPTER_ETHERNET;
			}
			if (type & MIB_IF_TYPE_LOOPBACK) {
				na.TypeFlags = na.TypeFlags | NETWORK_ADAPTER_LOOPBACK;
			}
			if (type & IF_TYPE_IEEE80211) {
				na.TypeFlags = na.TypeFlags | NETWORK_ADAPTER_IEEE801Wireless;
			}
			if ((type & MIB_IF_TYPE_OTHER) ||
				(type & IF_TYPE_ISO88025_TOKENRING) ||
				(type & MIB_IF_TYPE_PPP) ||
				(type & MIB_IF_TYPE_SLIP)) {
				na.TypeFlags = na.TypeFlags | NETWORK_ADAPTER_OtherOrUnknown;
			}
			result.push_back(na);
			adapterInfo = adapterInfo->Next;
		}
		// delete[] adapterInfo;
#else
    struct ifaddrs* ifAddrStruct = nullptr;
    struct ifaddrs* ifa = nullptr;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) { // IPv4
            NetworkAdapter na;
            na.Name = ifa->ifa_name;

            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            char ipAddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ipAddr, INET_ADDRSTRLEN);
            na.IPv4Address.push_back(ipAddr);

            struct sockaddr_in* mask = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);
            char maskAddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(mask->sin_addr), maskAddr, INET_ADDRSTRLEN);
            na.SubnetAddress.push_back(maskAddr);

            // Calculate broadcast address
            struct sockaddr_in broadcastAddr;
            memset(&broadcastAddr, 0, sizeof(broadcastAddr));
            broadcastAddr.sin_family = AF_INET;
            broadcastAddr.sin_addr.s_addr = (addr->sin_addr.s_addr & mask->sin_addr.s_addr) | ~mask->sin_addr.s_addr;
            char broadcastStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(broadcastAddr.sin_addr), broadcastStr, INET_ADDRSTRLEN);
            na.BroadcastAddress.push_back(broadcastStr);

            // Get gateway address
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            ioctl(fd, SIOCGIFADDR, &ifr);
            close(fd);
            na.GatewayAddress = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);

            // Fill other fields as needed
            na.Description = ""; // You can set the description based on the interface type or other information
            na.TypeFlags = 0; // You can set type flags based on interface properties

            result.push_back(na);
        }
    }

    if (ifAddrStruct != nullptr) freeifaddrs(ifAddrStruct);

    return result;
#endif
		return result;
	}

	Socket& Socket::SetReuseAddrOption(bool value)
	{
		int enable = value ? 1 : 0;
		if (setsockopt(mSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable, sizeof(int)) < 0) {
			throw std::runtime_error("Could not enable Reuse Addr.");
		}
		return *this;
	}

	Socket& Socket::JoinMulticastGroup(const std::string& GroupAddress)
	{
		struct ip_mreq mreq;
		mreq.imr_multiaddr.s_addr = ::inet_addr(GroupAddress.c_str());
		mreq.imr_interface.s_addr = ::inet_addr("192.168.1.76");
		if (setsockopt(mSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) < 0) {
			throw std::runtime_error("Failed to join multicast group.");
		}
		//		in_addr localInterface{};
		//		localInterface.s_addr = inet_addr(GroupAddress.c_str());
		//		if (setsockopt(mSocket, IPPROTO_IP, IP_MULTICAST_IF, (char*)&localInterface, sizeof(localInterface)) < 0)
		//
		//		{
		//			throw std::runtime_error("Failed to join multicast group. (2)");
		//}
		return *this;
	}

	Socket& Socket::SetMulticastLoopOption(bool value)
	{
		int enable = value ? 1 : 0;
		setsockopt(mSocket, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&enable, sizeof(int));
		return *this;
	}


#endif

}
