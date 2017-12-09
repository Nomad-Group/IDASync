import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

class MakeDataSyncUpdate extends IdbUpdate {
    public ptr: Long;
    public len: Long;

    public flags: number;
}

export class MakeDataSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.MakeData;

    public decodePacket(updateData: MakeDataSyncUpdate, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
        updateData.len = packet.buffer.readUInt64();

        updateData.flags = packet.buffer.readUInt32();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: MakeDataSyncUpdate) {
        packet.buffer.writeUInt64(updateData.ptr);
        packet.buffer.writeUInt64(updateData.len);

        packet.buffer.writeUInt32(updateData.flags);
    }

    public getUniqueIdentifier(update: MakeDataSyncUpdate) {
        return null;
    }
}