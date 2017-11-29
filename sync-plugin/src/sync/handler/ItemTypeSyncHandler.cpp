#include "sync/handler/ItemTypeSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool ItemTypeSyncHandler::ApplyUpdateImpl(ItemTypeSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " Type changed");

	auto type = (const type_t*) updateData->type.c_str();
	
	const p_list* fnames = nullptr;
	if (!updateData->fnames.empty())
		fnames = (const p_list*)updateData->fnames.c_str();
	
	tinfo_t tinf;
	tinf.deserialize(idati, &type, &fnames);
	return set_tinfo2(static_cast<ea_t>(updateData->ptr), &tinf);
}

bool ItemTypeSyncHandler::HandleNotification(IdaNotification& notification, ItemTypeSyncUpdateData* updateData)
{
	updateData->ptr  = static_cast<uint64_t>(va_arg(notification.args, ea_t));
	updateData->type = va_arg(notification.args, const char*); // type_t = char

	const char* fnames = va_arg(notification.args, const char*); // p_list = char
	if(fnames)
		updateData->fnames = fnames;

	return true;
}

void ItemTypeSyncHandler::DecodePacketImpl(ItemTypeSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
	updateData->type = packet->ReadString();
	updateData->fnames = packet->ReadString();
}

void ItemTypeSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, ItemTypeSyncUpdateData* updateData)
{
	packet->Write(updateData->ptr);
	packet->WriteString(updateData->type.c_str());
	packet->WriteString(updateData->fnames.c_str());
}