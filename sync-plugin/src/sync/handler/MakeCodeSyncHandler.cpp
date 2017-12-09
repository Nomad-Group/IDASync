#include "sync/handler/MakeCodeSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"

bool MakeCodeSyncHandler::ApplyUpdateImpl(MakeCodeSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " create instruction");

	return create_insn(static_cast<ea_t>(updateData->ptr));
}

bool MakeCodeSyncHandler::HandleNotification(IdaNotification& notification, MakeCodeSyncUpdateData* updateData)
{
	updateData->ptr = static_cast<uint64_t>(va_arg(notification.args, ea_t));
	//updateData->len = static_cast<uint64_t>(va_arg(notification.args, asize_t));

	return true;
}

void MakeCodeSyncHandler::DecodePacketImpl(MakeCodeSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
}

void MakeCodeSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, MakeCodeSyncUpdateData* updateData)
{
	packet->Write(&updateData->ptr);
}