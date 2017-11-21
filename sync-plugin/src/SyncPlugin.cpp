#include "SyncPlugin.h"
#include "network/Networking.h"
#include "network/NetworkClient.h"
#include "network/packets/HandshakePacket.h"
#include <ida.hpp>
#include <idp.hpp>

SyncPlugin* g_plugin = nullptr;

bool SyncPlugin::Init()
{
	bool isX86 = strncmp(inf.procName, "metapc", 8) != 0;

	// IDB Hook
	if (!InstallIDBHook())
	{
		Log("Error: Failed to install IDB Hook!");
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
	// Networking
	if (g_client)
		delete g_client;

	Networking::GlobalShutdown();
}

void SyncPlugin::Run()
{
	std::string ip = "127.0.0.1";
	if (!g_client->Connect(ip))
		return;

	// Hardware ID
	HandshakePacket packet;
	packet.packetType = PacketType::Handshake;
	memcpy(&packet.guid, Networking::GetHardwareId().c_str(), sizeof(packet.guid));
	retrieve_input_file_md5(packet.binarymd5);

	// Handshake
	g_plugin->Log("Connected to " + ip + ", shaking hands..");

	if (!g_client->Send(&packet))
	{
		g_plugin->ShowInfoDialog("Handshake failed!");
		return;
	}

	// Receive HandshakeResponse
	HandshakeResponsePacket packetResponse;
	if (!g_client->ExpectPacket(&packetResponse))
	{
		g_plugin->ShowInfoDialog("Expected HandshakeResponse Packet!");
		return;
	}

	// Connected
	g_client->StartListening();
}

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