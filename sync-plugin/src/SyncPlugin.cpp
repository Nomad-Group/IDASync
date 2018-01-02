#include "SyncPlugin.h"
#include "ida/IdbManager.h"
#include "sync/SyncManager.h"
#include "network/Networking.h"
#include "network/NetworkClient.h"
#include "network/NetworkBuffer.h"
#include "UI/UIFunctions.h"

#include <ida.hpp>
#include <idp.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

SyncPlugin* g_plugin = nullptr;

int idaapi ui_event(void *user_data, int notification_code, va_list va)
{
	if (notification_code == ui_notification_t::ui_ready_to_run && g_idb->HasPersistentData())
	{
		UIShowStatusBar();
		UIStatusBarSetColor("red");

		if (UIShowAutoConnectStartupDialog())
			g_plugin->Run();
	}

	return 0;
}

bool SyncPlugin::Init()
{
	// Idb Manager
	g_idb = new IdbManager();
	hook_to_notification_point(hook_type_t::HT_UI, ui_event, nullptr);

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
	// Status Bar
	UIHideStatusBar();

	// Idb Manager
	delete g_idb;
	g_idb = nullptr;

	// Networking
	if (g_client)
	{
		g_client->Disconnect();
		delete g_client;
		g_client = nullptr;
	}

	Networking::GlobalShutdown();
}

void SyncPlugin::Run()
{
	// Disconnect?
	if (g_client->IsConnected())
	{
		g_client->Disconnect();
		return;
	}

	// Reset
	m_heartbeatService.Reset();
	m_uiUpdateOperationTotalUpdates = 0;

	// Status Bar
	UIShowStatusBar();
	UIStatusBarSetColor("orange");

	// Idb Manager
	if (!g_idb->Initialize())
	{
		Log("Error: Failed to initialize IdbManager!");
		UIStatusBarSetColor("red");

		return;
	}

	// Connect
#ifdef _DEBUG
	std::string ip = "127.0.0.1";
#else
	std::string ip = "62.75.142.79";
#endif

	//ip = "62.75.142.79";

	if (!g_client->Connect(ip))
	{
		UIStatusBarSetColor("red");
		return;
	}

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

	// Client Version
	packet->Write(VERSION_NUMBER);

	// Handshake Packet
	packet->t->packetType = PacketType::Handshake;
	packet->t->packetSize = static_cast<uint16_t>(packet->GetSize());

	if (!g_client->Send(packet))
	{
		g_plugin->Log("Handshake failed!");
		UIStatusBarSetColor("red");

		delete packet;
		return;
	}

	delete packet;

	// Receive HandshakeResponse
	auto packetResponse = new NetworkBufferT<BasePacket>();

	if (!g_client->ReadPacket(packetResponse))
	{
		g_plugin->Log("Handshake failed!");
		UIStatusBarSetColor("red");

		delete packetResponse;
		return;
	}

	// Success?
	if (!packetResponse->ReadBool())
	{
		g_plugin->Log("Handshake failed: " + packetResponse->ReadString());
		UIStatusBarSetColor("red");
		
		delete packetResponse;
		return;
	}

	// Listener
	if (!g_client->StartListening(&m_dispatcher))
	{
		g_plugin->Log("Unable to start Network Listener.. Disconnecting!");
		g_client->Disconnect();
		UIStatusBarSetColor("red");

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

	// Status Bar
	UIStatusBarSetColor("green");
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