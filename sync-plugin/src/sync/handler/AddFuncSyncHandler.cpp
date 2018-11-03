#include "sync/handler/AddFuncSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <name.hpp>

bool AddFuncSyncHandler::ApplyUpdateImpl(AddFuncSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptrStart) + "-" + number2hex(updateData->ptrEnd) + " add function");

	return add_func(static_cast<ea_t>(updateData->ptrStart), static_cast<ea_t>(updateData->ptrEnd));
}

bool AddFuncSyncHandler::HandleNotification(IdaNotification& notification, AddFuncSyncUpdateData* updateData)
{
	func_t* func = va_arg(notification.args, func_t*);
	if (func == nullptr)
		return false;

	updateData->ptrStart = static_cast<uint64_t>(func->start_ea);
	updateData->ptrEnd = static_cast<uint64_t>(func->end_ea);

	return true;
}

void AddFuncSyncHandler::DecodePacketImpl(AddFuncSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptrStart);
	packet->Read(&updateData->ptrEnd);
}

void AddFuncSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, AddFuncSyncUpdateData* updateData)
{
	packet->Write(&updateData->ptrStart);
	packet->Write(&updateData->ptrEnd);
}