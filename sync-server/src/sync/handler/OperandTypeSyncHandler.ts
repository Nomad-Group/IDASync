import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

enum OperandType {
    _Unsupported = 255,

    Unknown = 0,
    Enum = 1,               // Unsupported
    StructOffset = 2,       // Unsupported
    Offset = 3
}

class OperandTypeOffsetData {
    public flags: number;
    public base: Long;
    public target: Long;
    public delta: Long;
}

class OperandTypeSyncUpdate extends IdbUpdate {
    public ptr: Long;
    public numOperands: number;
    public flags: number;

    public operandType: OperandType;

    public data: OperandTypeOffsetData; // | OperandType...Data | ...;
}

export class OperandTypeSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.OperandType;

    public decodePacket(updateData: OperandTypeSyncUpdate, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
        updateData.numOperands = packet.buffer.readUInt8();
        updateData.flags = packet.buffer.readUInt32();

        updateData.operandType = packet.buffer.readUInt8();
        switch (updateData.operandType) {
            case OperandType.Offset: {
                var data = new OperandTypeOffsetData();
                data.flags = packet.buffer.readUInt32();
                data.base = packet.buffer.readUInt64();
                data.target = packet.buffer.readUInt64();
                data.delta = packet.buffer.readInt64();

                updateData.data = data;
            }
        }
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: OperandTypeSyncUpdate) {
        packet.buffer.writeUInt64(updateData.ptr);
        packet.buffer.writeUInt8(updateData.numOperands);
        packet.buffer.writeUInt32(updateData.flags);

        packet.buffer.writeUInt8(updateData.operandType);
        switch (updateData.operandType) {
            case OperandType.Offset: {
                var data = <OperandTypeOffsetData>updateData.data;

                packet.buffer.writeUInt32(data.flags);
                packet.buffer.writeUInt64(data.base);
                packet.buffer.writeUInt64(data.target);
                packet.buffer.writeInt64(data.delta);
            }
        }
    }

    public getUniqueIdentifier(update: OperandTypeSyncUpdate) {
        return {
            ptr: update.ptr,
        }
    }
}