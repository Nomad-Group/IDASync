#include "sync/handler/AddFuncSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <name.hpp>

bool AddFuncSyncHandler::ApplyUpdate(IdbUpdate* _updateData)
{
	auto updateData = (AddFuncSyncUpdateData*)_updateData;
	g_plugin->Log(number2hex(updateData->ptrStart) + "-" + number2hex(updateData->ptrEnd) + " add function");

	return add_func(static_cast<ea_t>(updateData->ptrStart), static_cast<ea_t>(updateData->ptrEnd));
}

bool AddFuncSyncHandler::OnIdaNotification(IdaNotification& notification)
{
	// Renamed Notification
	if (notification.type != IdaNotificationType::idp || notification.code != processor_t::add_func)
		return false;

	// Args
	func_t* func = va_arg(notification.args, func_t*);

	// Update
	auto update = new AddFuncSyncUpdateData();
	update->syncType = SyncType::AddFunc;

	update->ptrStart = static_cast<decltype(update->ptrStart)>(func->startEA);
	update->ptrEnd = static_cast<decltype(update->ptrEnd)>(func->endEA);

	// Send
	g_syncManager->SendUpdate(update);
	return true;
}

IdbUpdate* AddFuncSyncHandler::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	auto updateData = new AddFuncSyncUpdateData();

	// Data
	packet->Read(&updateData->ptrStart);
	packet->Read(&updateData->ptrEnd);

	return updateData;
}

bool AddFuncSyncHandler::EncodePacket(NetworkBufferT<BasePacket>* packet, IdbUpdate* _updateData)
{
	auto updateData = (AddFuncSyncUpdateData*)_updateData;

	// Data
	packet->Write(&updateData->ptrStart);
	packet->Write(&updateData->ptrEnd);

	return true;
}