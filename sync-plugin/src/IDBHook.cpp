#include "SyncPlugin.h"
#include "Utility.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#include "ida/idb_events_strings.h"
#include "ida/idp_events_strings.h"

#include "ida/IdbManager.h"

#include "network/NetworkClient.h"
#include "network/packets/BaseIdbUpdatePacket.h"

int idaapi idb_hook(void*, int notification_code, va_list va)
{
	//g_plugin->Log(std::string("IDB: ") + idb_events_strings[notification_code]);
	return 0;
}

int idaapi idp_hook(void*, int notification_code, va_list va)
{
	//g_plugin->Log(std::string("IDP: ") + idp_events_strings[notification_code]);
	
	if (notification_code == processor_t::renamed)
	{
		ea_t ea = va_arg(va, ea_t);
		const char *name = va_arg(va, const char *);
		bool local = va_arg(va, int) != 0;

		g_plugin->Log(number2hex(ea) + ": Rename to " + std::string(name));

		auto packet = new NetworkBufferT<BasePacket>();
		packet->t->packetType = PacketType::IdbUpdate;
		
		packet->Write<uint32_t>(0); // version
		packet->Write<uint16_t>(0); // syncType
		//packet->t->syncType = 0;

		packet->Write(static_cast<uint64_t>(ea));
		packet->WriteString(name);

		packet->t->packetSize = packet->GetSize();
		g_client->Send(packet);
		delete packet;

		/*auto packet = new IdbNameAddressPacket();
		packet->binaryVersion = g_idb->GetVersion();
		packet->ptr = static_cast<uint64_t>(ea);
		strcpy_s(packet->name, name);*/

		//g_client->Send(packet);
	}
	
	return 0;
}

bool SyncPlugin::InstallIDBHook()
{
	return
		hook_to_notification_point(hook_type_t::HT_IDB, idb_hook, nullptr) &&
		hook_to_notification_point(hook_type_t::HT_IDP, idp_hook, nullptr);
}