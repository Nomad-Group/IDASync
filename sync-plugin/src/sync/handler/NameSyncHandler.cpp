#include "sync/handler/NameSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <name.hpp>

bool NameSyncHandler::ApplyUpdate(IdbUpdate* _updateData)
{
	auto updateData = (NameSyncUpdateData*)_updateData;
	g_plugin->Log(number2hex(updateData->ptr) + " was named " + updateData->name);

	return set_name(static_cast<ea_t>(updateData->ptr), updateData->name.c_str(), (updateData->local ? SN_LOCAL : 0) | SN_NOWARN);
}

bool NameSyncHandler::OnIdaNotification(IdaNotification& notification)
{
	// Renamed Notification
	if (notification.type != IdaNotificationType::idp || notification.code != processor_t::renamed)
		return false;

	// Args
	ea_t ea = va_arg(notification.args, ea_t);
	const char *name = va_arg(notification.args, const char*);
	bool local = va_arg(notification.args, int) != 0;

	// Update
	auto update = new NameSyncUpdateData();
	update->syncType = SyncType::Name;

	update->ptr = static_cast<decltype(update->ptr)>(ea);
	update->name = name;
	update->local = local;

	// Send
	g_syncManager->SendUpdate(update);
	return true;
}

IdbUpdate* NameSyncHandler::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	auto updateData = new NameSyncUpdateData();
	
	// Data
	packet->Read(&updateData->ptr);

	auto str = packet->ReadString();
	if (str == nullptr)
	{
		delete updateData;
		return nullptr;
	}

	updateData->name = str;
	updateData->local = packet->ReadBool();
	return updateData;
}

bool NameSyncHandler::EncodePacket(NetworkBufferT<BasePacket>* packet, IdbUpdate* _updateData)
{
	auto updateData = (NameSyncUpdateData*)_updateData;

	// Data
	packet->Write(updateData->ptr);
	packet->WriteString(updateData->name.c_str());
	packet->WriteBool(updateData->local);

	return true;
}