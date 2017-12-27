#include "SyncPlugin.h"
#include "ida/IdbManager.h"
#include "sync/SyncManager.h"
#include "network/Networking.h"
#include "network/NetworkClient.h"
#include "network/NetworkBuffer.h"
#include <ida.hpp>
#include <idp.hpp>

SyncPlugin* g_plugin = nullptr;

bool SyncPlugin::Init()
{
	// Idb Manager
	g_idb = new IdbManager();
	if (!g_idb->Initialize())
	{
		Log("Error: Failed to initialize IdbManager!");
		return false;
	}

	// Sync Manager
	g_syncManager = new SyncManager();
	if (!g_syncManager->Initialize())
	{
		Log("Error: Failed to initialize Sync Manager!");
		return false;
	}

	// Networking
	if (!Networking::GlobalInit())
	{
		Log("Error: Failed to initialize Networking!");
		return false;
	}

	g_client = new NetworkClient();

	// Done
	return true;
}

void SyncPlugin::Shutdown()
{
	// Idb Manager
	delete g_idb;
	g_idb = nullptr;

	// Networking
	if (g_client)
	{
		g_client->Disconnect();
		delete g_client;
	}

	Networking::GlobalShutdown();
}

void Test();

void SyncPlugin::Run()
{
	Test();

#ifdef _DEBUG
	std::string ip = "127.0.0.1";
#else
	std::string ip = "62.75.142.79";
#endif

	if (!g_client->Connect(ip))
		return;

	// Handshake
	auto packet = new NetworkBufferT<BasePacket>();

	// Hardware ID
	packet->Write(Networking::GetHardwareId().c_str(), 38);
	
	// Username
	{
		char username[64] = { 0 };

		DWORD stUsernameSize = sizeof(username);
		GetUserName(username, &stUsernameSize);
		packet->Write(username, stUsernameSize);
	}

	// Binary
	// md6
	retrieve_input_file_md5((uchar*) packet->WritePtr(16));
	
	// Filename
	{
		char buffer[128];
		size_t stFilenameSize = get_root_filename(buffer, sizeof(buffer) - 1) + 1;
		packet->WriteString(buffer);
	}

	// Idb Version
	packet->Write(g_idb->GetVersion());

	// Handshake Packet
	packet->t->packetType = PacketType::Handshake;
	packet->t->packetSize = static_cast<uint16_t>(packet->GetSize());

	if (!g_client->Send(packet))
	{
		g_plugin->Log("Handshake failed!");

		delete packet;
		return;
	}

	delete packet;

	// Receive HandshakeResponse
	auto packetResponse = new NetworkBufferT<BasePacket>();

	if (!g_client->ReadPacket(packetResponse))
	{
		g_plugin->Log("Handshake failed!");
		delete packetResponse;
		return;
	}

	// Listener
	if (!g_client->StartListening(&m_dispatcher))
	{
		g_plugin->Log("Unable to start Network Listener.. Disconnecting!");
		g_client->Disconnect();
		delete packetResponse;
		return;
	}

	// Connected!
	auto username = packetResponse->ReadString();
	auto project  = packetResponse->ReadString();

	uint32_t remoteVersion = 0;
	packetResponse->Read(&remoteVersion);

	g_plugin->Log("Successfully connected as " + username + " (project: " + project + ")");
	g_plugin->Log("Local Version: " + std::to_string(g_idb->GetVersion()) + ", Remote Version: " + std::to_string(remoteVersion));

	delete packetResponse;
}

// Logging
void SyncPlugin::Log(const std::string& message)
{
	msg("[SyncPlugin] %s\n", message.c_str());
}
void SyncPlugin::ShowErrorDialog(const std::string& message)
{
	error("[SyncPlugin] %s\n", message.c_str());
}
void SyncPlugin::ShowInfoDialog(const std::string& message)
{
	info("[SyncPlugin] %s\n", message.c_str());
}