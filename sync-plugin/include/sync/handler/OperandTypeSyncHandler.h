#pragma once
#include "sync/SyncHandlerImpl.h"

enum class OperandType : uint8_t
{
	_Unsupported = UINT8_MAX,

	Unknown = 0,
	Enum = 1,			// Unsupported
	StructOffset = 2,	// Unsupported
	Offset = 3,
};

struct OperandTypeSyncUpdateData : IdbUpdateData
{
	uint64_t ptr;
	uint8_t numOperands;
	uint32_t flags; // flag_t = uint32

	OperandType operandType = OperandType::Unknown;
	union
	{
		// OperandType::Offset
		struct
		{
			uint32_t flags;
			uint64_t base;
			uint64_t target;
			int64_t delta;
		} dataOffset;
	};
};

class OperandTypeSyncHandler : public SyncHandlerImpl<OperandTypeSyncUpdateData, SyncType::OperandType>
{
public:
	OperandTypeSyncHandler() : SyncHandlerImpl(IdaNotificationType::idb, idb_event::op_type_changed)
	{}

protected:
	virtual bool ApplyUpdateImpl(OperandTypeSyncUpdateData*) override;
	virtual bool HandleNotification(IdaNotification&, OperandTypeSyncUpdateData*) override;

	virtual void DecodePacketImpl(OperandTypeSyncUpdateData*, NetworkBufferT<BasePacket>*) override;
	virtual void EncodePacketImpl(NetworkBufferT<BasePacket>*, OperandTypeSyncUpdateData*) override;
};