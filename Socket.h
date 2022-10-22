#pragma once
#include <stdint.h>
#include <stdbool.h>
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
#include <assert.h>

// #define SOCKET_C_IMPLEMENTATION

enum e_socket_type {
	SOCKET_TYPE_TCP = 1,
	SOCKET_TYPE_UDP = 2
};

enum e_socket_interface {
	// Accept connections only from localhost interface
	SOCKET_INTERFACE_LOOPBACK = 1,
	// Accept connection from any interface
	SOCKET_INTERFACE_ANY = 2,
	SOCKET_INTERFACE_CUSTOM_INTERFACE = 3
};

// Invalid Socket have handle == 0
struct s_socket {
	uint64_t handle;
	bool is_connected;
	bool is_blocking;
	bool keep_alive;
	sockaddr_in endpoint;
	e_socket_type socket_type;
};

void sw_startup();
void sw_cleanup();

s_socket sw_createsocket(e_socket_type type);

/// <summary>
/// Bind socket to specified port
/// A port of 0 lets the os to decide the post
/// call listen after this function
/// </summary>
/// <param name="socket">Socket Reference created by sw_createsocket</param>
/// <param name="port">A port of 0 lets the os to decide the post</param>
bool sw_bind(s_socket* socket, e_socket_interface sinterface, uint16_t port, char* custom_interface_address);

/// <summary>
/// Listen must be called after bind()
/// This function determines how many connections can be queued before accepting
/// the client connection
/// </summary>
bool sw_listen(s_socket* socket, uint16_t max_connection_backlog);

/// <summary>
/// Accepts client connection
/// Must call bind() and listen() before this function
/// </summary>
/// <param name="socket"></param>
/// <returns></returns>
s_socket sw_accept(s_socket* socket);

bool sw_connect(s_socket* socket, const char* ip_address, uint16_t port);
void sw_disconnect(s_socket* socket);

void sw_closesocket(s_socket* socket);

void sw_socket_set_blockingmode(s_socket* socket, bool blocking_mode);

/// <summary>
/// Nagle algorithim waits until the Send() packets are large enough before actually sending them.
/// Therefore potentially increasing latency.
/// By default it is enabled.
/// </summary>
/// <param name="State">True/False => Enable/Disable</param>
void sw_set_nagle_algorthim(s_socket* socket, bool State);

/// <summary>
/// Sends TCP Packets (does not affect client/server application)
/// to check connection state (in case the application didn't have a proper disconnection)
/// </summary>
/// <param name="State">Enable/Disable</param>
void sw_set_tcp_keep_alive(s_socket* socket, bool State, uint8_t KeepAliveProbeCount);

void sw_enable_broadcast(s_socket* socket);

void sw_wait_for_data(s_socket* socket);
void sw_nwait_for_data(uint_fast16_t count, s_socket* sockets);

uint32_t sw_tcp_send(s_socket* socket, const void* data, int32_t size);
uint32_t sw_tcp_recv(s_socket* socket, int32_t size, char* output_buffer, bool wait_all, bool peek);

uint16_t sw_udp_send(s_socket* socket, const char* dest_ip, uint16_t dest_port, const void* data, int32_t size);
uint16_t sw_udp_recv(s_socket* socket, char* output_buffer, int32_t size, char* optional_packet_source_ip, uint16_t* optional_packet_source_port);

#ifdef SOCKET_C_IMPLEMENTATION
#ifndef _WIN32
#define closesocket(...) close(__VA_ARGS__)
#define ioctlsocket(...) ioctl(__VA_ARGS__)
#define SD_BOTH SHUT_RDWR
#endif

void sw_startup()
{
#ifdef _WIN32
	WSADATA ws;
	WSAStartup(MAKEWORD(2, 2), &ws);
#endif
}

void sw_cleanup()
{
#ifdef _WIN32
	WSACleanup();
#endif
}

s_socket sw_createsocket(e_socket_type type)
{
	s_socket sock;
	memset(&sock, 0, sizeof(s_socket));
	sock.is_blocking = true;
	if (type == SOCKET_TYPE_TCP) {
		sock.handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (SOCKET_TYPE_UDP) {
		sock.handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else {
		assert(0);
	}
	return sock;
}

bool sw_bind(s_socket* socket, e_socket_interface sinterface, uint16_t port, char* custom_interface_address)
{
	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (sinterface == SOCKET_INTERFACE_LOOPBACK) {
		addr.sin_addr.s_addr = INADDR_LOOPBACK;
	}
	else if (sinterface == SOCKET_INTERFACE_ANY) {
		addr.sin_addr.s_addr = INADDR_ANY;
	}
	else if (sinterface == SOCKET_INTERFACE_CUSTOM_INTERFACE) {
		addr.sin_addr.s_addr = inet_addr(custom_interface_address);
	}
	else {
		assert(0);
	}
	return bind(socket->handle, (sockaddr*)&addr, sizeof(sockaddr_in)) == 0;
}

bool sw_listen(s_socket* socket, uint16_t max_connection_backlog)
{
	assert(socket->socket_type == SOCKET_TYPE_TCP);
	return listen(socket->handle, max_connection_backlog) == 0;
}

s_socket sw_accept(s_socket* socket)
{
	s_socket result;
	memset(&result, 0, sizeof(s_socket));
	int len = sizeof(sockaddr_in);
	result.handle = accept(socket->handle, (sockaddr*)&result.endpoint, &len);
	return result;
}

bool sw_connect(s_socket* socket, const char* ip_address, uint16_t port)
{
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip_address);
	socket->is_connected = connect(socket->handle, (sockaddr*)&addr, sizeof(sockaddr_in)) == 0;
	return socket->is_connected;
}

void sw_disconnect(s_socket* socket)
{
	shutdown(socket->handle, SD_BOTH);
}

void sw_closesocket(s_socket* socket)
{
	closesocket(socket->socket_type);
}

void sw_socket_set_blockingmode(s_socket* socket, bool blocking_mode)
{
	if (socket->is_blocking == blocking_mode) return;
	assert(socket->socket_type != SOCKET_TYPE_TCP && "Cannot set blocking mode on RAW Socket");
	u_long code = blocking_mode ? 0 : 1;
	if (ioctlsocket(socket->handle, FIONBIO, &code) == 0)
		socket->is_blocking = blocking_mode;
}

void sw_set_nagle_algorthim(s_socket* socket, bool state)
{
	uint32_t state = state ? 1 : 0;
	setsockopt(socket->handle, SOL_SOCKET, TCP_NODELAY, (const char*)&state, sizeof(uint32_t));
}

void sw_set_tcp_keep_alive(s_socket* socket, bool State, uint8_t KeepAliveProbeCount)
{
	uint32_t state = State ? 1 : 0;
	setsockopt(socket->handle, SOL_SOCKET, SO_KEEPALIVE, (const char*)&state, sizeof(uint32_t));
	uint32_t propeCount = KeepAliveProbeCount;
	setsockopt(socket->handle, IPPROTO_TCP, TCP_KEEPCNT, (const char*)&propeCount, sizeof(uint32_t));
	socket->keep_alive = State;
}

void sw_wait_for_data(s_socket* socket)
{
#ifdef _WIN32
	WSAPOLLFD fdArray{};
	fdArray.fd = socket->socket_type;
	fdArray.events = POLLRDNORM;
	WSAPoll(&fdArray, 1, INFINITE);
#else
#error "Not IMplemented"
#endif
}

void sw_nwait_for_data(uint_fast16_t count, s_socket* sockets)
{
	if (count == 0) return;
#ifdef _WIN32
	WSAPOLLFD* fdArray = (WSAPOLLFD*)malloc(sizeof(WSAPOLLFD) * count);
	if (!fdArray)
		return;
	for (int i = 0; i < count; i++) {
		fdArray[i].fd = sockets[i].handle;
		fdArray[i].events = POLLRDNORM;
	}
	WSAPoll(fdArray, (ULONG)count, INFINITE);
	free(fdArray);
#else
#error "Not supported"
#endif
}

static bool sw_internal_getconnectionstate() {
#ifdef _WIN32
	int error = WSAGetLastError();
	return (error == WSAEWOULDBLOCK) || (error == WSAEOPNOTSUPP);
#else
#error "Not supported"
#endif
}

uint32_t sw_tcp_send(s_socket* socket, const void* data, int32_t size)
{
	if (size == 0) return;
	int32_t readBytes = send(socket->handle, (const char*)data, size, 0);
	if (readBytes == 0) socket->is_connected = false;
	else if (readBytes < 0) {
		socket->is_connected = sw_internal_getconnectionstate();
		readBytes = 0;
	}
	return readBytes;
}

uint32_t sw_tcp_recv(s_socket* socket, int32_t size, char* output_buffer, bool wait_all, bool peek)
{
	if (wait_all && !socket->is_blocking)
		assert(0 && "Cannot use WaitAll with Non-Blocking sockets.");

	if (wait_all && peek)
		assert(0, "Cannot use WaitAll and Peek at the same time.");

	int flags = (peek ? MSG_PEEK : 0) | (wait_all ? MSG_WAITALL : 0);
	int32_t recvBytes = recv(socket->handle, (char*)output_buffer, size, flags);
	if (recvBytes == 0) {
		socket->handle = false;
		return 0;
	}
	if (recvBytes < 0)
	{
		socket->is_connected = sw_internal_getconnectionstate();
		return 0;
	}
	return recvBytes;
}

uint16_t sw_udp_send(s_socket* socket, const char* dest_ip, uint16_t dest_port, const void* data, int32_t size)
{
	if (size == 0) return;
	sockaddr_in dest{};
	dest.sin_addr.s_addr = inet_addr(dest_ip);
	dest.sin_family = AF_INET;
	dest.sin_port = htons(dest_port);
	socklen_t len = sizeof(dest);
	int sentBytes = sendto(socket->handle, (const char*)data, size, 0, (sockaddr*)&dest, len);
	return sentBytes;
}

uint16_t sw_udp_recv(s_socket* socket, int32_t size, char* output_buffer, char* optional_packet_source_ip, uint16_t* optional_packet_source_port)
{
	sockaddr_in src{};
	socklen_t len = sizeof(src);
	int recvBytes = recvfrom(socket->handle, (char*)output_buffer, size, 0, (sockaddr*)&src, &len);
	if (optional_packet_source_ip && optional_packet_source_port)
	{
		*optional_packet_source_ip = inet_ntoa(src.sin_addr);
		*optional_packet_source_port = ntohs(src.sin_port);
	}
	return recvBytes;
}

void sw_enable_broadcast(s_socket* socket)
{
	int enabled = 1;
	setsockopt(socket->handle, SOL_SOCKET, SO_BROADCAST, (const char*)&enabled, sizeof(enabled));
}

#endif
