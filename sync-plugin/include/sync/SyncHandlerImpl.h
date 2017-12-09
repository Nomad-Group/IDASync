#pragma once
#include "sync/ISyncHandler.h"
#include "sync/IdbUpdateData.h"

#include "SyncPlugin.h"
#include "sync/SyncManager.h"

template <class TUpdateDataType, SyncType TSyncType>
class SyncHandlerImpl : public ISyncHandler
{
	static constexpr const SyncType SYNC_TYPE = TSyncType;

	// Notification
	IdaNotificationType m_notificationType;
	int m_notificationCode;

	// IdbUpdateData
	inline TUpdateDataType* CreateUpdateData()
	{ 
		auto updateData = new TUpdateDataType();
		updateData->syncType = SYNC_TYPE;

		return updateData;
	}

protected:
	SyncHandlerImpl() = default;

	SyncHandlerImpl(IdaNotificationType notificationType, int notificationCode) :
		m_notificationType(notificationType),
		m_notificationCode(notificationCode)
	{}

	virtual bool ApplyUpdateImpl(TUpdateDataType*) = 0;

	virtual bool ShouldHandleNotification(IdaNotification& notification)
	{
		return
			notification.type == m_notificationType &&
			notification.code == m_notificationCode;
	}
	virtual bool HandleNotification(IdaNotification&, TUpdateDataType*) = 0;

	virtual void DecodePacketImpl(TUpdateDataType*, NetworkBufferT<BasePacket>*) = 0;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, TUpdateDataType*) = 0;

public:
	virtual bool ApplyUpdate(IdbUpdateData* updateData) override
	{
		return ApplyUpdateImpl((TUpdateDataType*)updateData);
	}

	virtual bool OnIdaNotification(IdaNotification& notification) override
	{
		if (!ShouldHandleNotification(notification))
			return false;

		auto updateData = CreateUpdateData();
		if (!HandleNotification(notification, updateData))
			g_plugin->Log("ERROR: SyncHandlerImpl::HandleNotification failed! SyncType: " + std::to_string((uint16_t) SYNC_TYPE));
		else
			g_syncManager->SendUpdate(updateData);

		delete updateData;
		return true;
	}

	virtual IdbUpdateData* DecodePacket(NetworkBufferT<BasePacket>* packet) override
	{
		auto updateData = CreateUpdateData();
		DecodePacketImpl(updateData, packet);

		return updateData;
	}
	virtual void EncodePacket(NetworkBufferT<BasePacket>* packet, IdbUpdateData* updateData) override
	{
		packet->t->packetType = PacketType::IdbUpdate;

		EncodePacketImpl(packet, (TUpdateDataType*)updateData);
	}
};