#include "sync/handler/NameSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <name.hpp>

bool NameSyncHandler::ApplyUpdateImpl(NameSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " was named " + updateData->name);

	return set_name(static_cast<ea_t>(updateData->ptr), updateData->name.c_str(), (updateData->local ? SN_LOCAL : 0) | SN_NOWARN);
}

bool NameSyncHandler::HandleNotification(IdaNotification& notification, NameSyncUpdateData* updateData)
{
	updateData->ptr = static_cast<uint64_t>(va_arg(notification.args, ea_t));
	updateData->name = va_arg(notification.args, const char*);
	updateData->local = va_arg(notification.args, int) != 0;

	return true;
}

void NameSyncHandler::DecodePacketImpl(NameSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
	updateData->name = packet->ReadString();
	updateData->local = packet->ReadBool();
}

void NameSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, NameSyncUpdateData* updateData)
{
	packet->Write(updateData->ptr);
	packet->WriteString(updateData->name);
	packet->WriteBool(updateData->local);
}