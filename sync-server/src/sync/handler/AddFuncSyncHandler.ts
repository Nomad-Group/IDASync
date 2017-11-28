import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

class AddFuncSyncUpdate extends IdbUpdate {
    public ptrStart: Long;
    public ptrEnd: Long;
}

export class AddFuncSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.Name;

    public decodePacket(updateData: AddFuncSyncUpdate, packet: IdbUpdatePacket) {
        updateData.ptrStart = packet.buffer.readUInt64();
        updateData.ptrEnd = packet.buffer.readUInt64();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: AddFuncSyncUpdate) {
        packet.buffer.writeUInt64(updateData.ptrStart);
        packet.buffer.writeUInt64(updateData.ptrEnd);
    }

    public getUniqueIdentifier(update: AddFuncSyncUpdate) {
        return {
            ptrStart: update.ptrStart,
            ptrEnd: update.ptrEnd
        }
    }
}