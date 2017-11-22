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
	{
		g_client->Disconnect();
		delete g_client;
	}

	Networking::GlobalShutdown();
}

struct PacketDispatcher : exec_request_t
{
	BasePacket* pPacket;

	virtual int idaapi execute()
	{
		g_plugin->Log("Hello from the main thread! Got your packet!");
		return 0;
	}
};

struct IDANetworkDispatcher : INetworkClientEventListener
{
	virtual void OnPacket(BasePacket* pPacket)
	{
		// ya ya lots of mem leaks, just proof of concept
		PacketDispatcher* dispatcher = new PacketDispatcher();
		dispatcher->pPacket = pPacket;

		execute_sync(*dispatcher, MFF_WRITE | MFF_NOWAIT);
	}
};

void SyncPlugin::Run()
{
	std::string ip = "127.0.0.1";
	if (!g_client->Connect(ip))
		return;

	// Hardware ID
	HandshakePacket* packet = new HandshakePacket();
	packet->packetType = PacketType::Handshake;
	memcpy(&packet->guid, Networking::GetHardwareId().c_str(), sizeof(HandshakePacket::guid));

	// Binary
	//retrieve_input_file_md5(packet.binary_md5);
	//get_root_filename(packet.binary_name, sizeof(packet.binary_name));

	// Handshake
	if (!g_client->Send(packet))
	{
		g_plugin->Log("Handshake failed!");
		return;
	}

	// Receive HandshakeResponse
	HandshakeResponsePacket* packetResponse = new HandshakeResponsePacket();
	if (!g_client->ReadPacket(packetResponse))
	{
		g_plugin->Log("Handshake failed!");
		return;
	}

	// Listener
	if (!g_client->StartListening(new IDANetworkDispatcher()))
	{
		g_plugin->Log("Unable to start Network Listener.. Disconnecting!");
		g_client->Disconnect();
		return;
	}

	// Connected!
	g_plugin->Log("Successfully connected to " + ip);
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