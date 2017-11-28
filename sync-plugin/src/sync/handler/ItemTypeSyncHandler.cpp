#include "sync/handler/ItemTypeSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool ItemTypeSyncHandler::ApplyUpdate(IdbUpdate* _updateData)
{
	auto updateData = (ItemTypeSyncUpdateData*)_updateData;
	g_plugin->Log(number2hex(updateData->ptr) + " Type changed");

	auto type = (const type_t*) updateData->type.c_str();
	
	const p_list* fnames = nullptr;
	if (!updateData->fnames.empty())
		fnames = (const p_list*)updateData->fnames.c_str();
	
	tinfo_t tinf;
	tinf.deserialize(idati, &type, &fnames);
	return set_tinfo2(static_cast<ea_t>(updateData->ptr), &tinf);
}

bool ItemTypeSyncHandler::OnIdaNotification(IdaNotification& notification)
{
	// Renamed Notification
	if (notification.type != IdaNotificationType::idb || notification.code != idb_event::ti_changed)
		return false;

	// Args
	ea_t ea = va_arg(notification.args, ea_t);
	const char* type = va_arg(notification.args, const char*); // type_t = char
	const char* fnames = va_arg(notification.args, const char*); // p_list = char

	// Update
	auto update = new ItemTypeSyncUpdateData();
	update->syncType = SyncType::ItemType;

	update->ptr = static_cast<uint64_t>(ea);
	update->type = type;

	if(fnames)
		update->fnames = fnames;

	// Send
	g_syncManager->SendUpdate(update);
	return true;
}

IdbUpdate* ItemTypeSyncHandler::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	auto updateData = new ItemTypeSyncUpdateData();

	// Data
	packet->Read(&updateData->ptr);
	updateData->type = packet->ReadString();

	auto fnames = packet->ReadString();
	if(fnames)
		updateData->fnames = fnames;

	return updateData;
}

bool ItemTypeSyncHandler::EncodePacket(NetworkBufferT<BasePacket>* packet, IdbUpdate* _updateData)
{
	auto updateData = (ItemTypeSyncUpdateData*)_updateData;

	// Data
	packet->Write(updateData->ptr);
	packet->WriteString(updateData->type.c_str());
	packet->WriteString(updateData->fnames.c_str());

	return true;
}