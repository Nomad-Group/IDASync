#include "network/Networking.h"
#include <WinSock2.h>
#include <Windows.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

static WSADATA* g_wsaData = nullptr;
bool Networking::GlobalInit()
{
	// WSAStartup
	g_wsaData = (WSADATA*)malloc(sizeof(WSADATA));
	return WSAStartup(MAKEWORD(2, 2), g_wsaData) == 0;
}

void Networking::GlobalShutdown()
{
	WSACleanup();

	delete g_wsaData;
	g_wsaData = nullptr;
}

std::string Networking::GetHardwareId()
{
	HW_PROFILE_INFO hwProfileInfo;
	if (!GetCurrentHwProfile(&hwProfileInfo))
		return std::string();

	return std::string(hwProfileInfo.szHwProfileGuid);
}