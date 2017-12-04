import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

class UndefineSyncUpdate extends IdbUpdate {
    public ptr: Long;
}

export class UndefineSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.Undefine;

    public decodePacket(updateData: UndefineSyncUpdate, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: UndefineSyncUpdate) {
        packet.buffer.writeUInt64(updateData.ptr);
    }

    public getUniqueIdentifier(update: UndefineSyncUpdate) {
        return {
            ptr: update.ptr,
        }
    }
}