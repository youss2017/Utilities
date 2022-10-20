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

struct s_endpoint {
	char* ip_address;
	uint16_t port;
};

enum e_socket_type {
	SOCKET_TYPE_TCP = 1,
	SOCKET_TYPE_UDP = 2
};

enum e_socket_interface {
	// Accept connections only from localhost interface
	SOCKET_INTERFACE_LOOPBACK = 1,
	// Accept connection from any interface
	SOCKET_INTERFACE_ANY = 2,
	// Local Broadcast is the IP Address of
	// 255.255.255.255
	// This will broadcast packets to immediate neigbors e.g.
	// computers in your local network, the packet will not 
	// be forwarded to other networks
	// For example: If a network subnet is 10.0.0.0/8
	// A direct broadcast would be 10.255.255.255
	// In which the packet will be forwaded to that network
	// whereas local broadcast only forwards packet to computers
	// on your network.
	SOCKET_INTERFACE_LOCAL_BROADCAST = 3,
	SOCKET_INTERFACE_CUSTOM_INTERFACE = 4
};

// Invalid Socket have handle == 0
struct s_socket {
	uint64_t handle;
	bool is_connected;
	bool is_blocking;
	bool keep_alive;
	s_endpoint endpoint;
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

void sw_connect(s_socket* socket, s_endpoint* endpoint);
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

void sw_wait_for_data(s_socket* socket);
void sw_mwait_for_data(uint_fast16_t count, s_socket** sockets);

uint32_t sw_tcp_send(s_socket* socket, const void* data, int32_t size);
uint32_t sw_tcp_recv(s_socket* socket, int32_t size, bool wait_all, bool peek);

uint16_t sw_udp_send(s_socket* socket, const char* dest_ip, uint16_t dest_port, const void* data, int32_t size);
uint16_t sw_udp_recv(s_socket* socket, int32_t size);


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
	else if (sinterface == SOCKET_INTERFACE_LOCAL_BROADCAST) {
		addr.sin_addr.s_addr = INADDR_BROADCAST;
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
	accept(socket->handle, )
}

void sw_connect(s_socket* socket, s_endpoint* endpoint)
{

}

void sw_disconnect(s_socket* socket)
{

}

void sw_closesocket(s_socket* socket)
{

}

void sw_socket_set_blockingmode(s_socket* socket, bool blocking_mode)
{

}

void sw_set_nagle_algorthim(s_socket* socket, bool state)
{

}

void sw_set_tcp_keep_alive(s_socket* socket, bool State, uint8_t KeepAliveProbeCount)
{

}

void sw_wait_for_data(s_socket* socket)
{

}

void sw_mwait_for_data(uint_fast16_t count, s_socket** sockets)
{

}

uint32_t sw_tcp_send(s_socket* socket, const void* data, int32_t size)
{

}

uint32_t sw_tcp_recv(s_socket* socket, int32_t size, bool wait_all, bool peek)
{

}

uint16_t sw_udp_send(s_socket* socket, const char* dest_ip, uint16_t dest_port, const void* data, int32_t size)
{

}

uint16_t sw_udp_recv(s_socket* socket, int32_t size)
{

}
