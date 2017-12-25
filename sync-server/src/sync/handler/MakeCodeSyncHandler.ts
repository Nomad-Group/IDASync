import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

class MakeCodeSyncUpdate extends IdbUpdate {
    public ptr: Long;
}

export class MakeCodeSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.MakeCode;

    public decodePacket(updateData: MakeCodeSyncUpdate, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: MakeCodeSyncUpdate) {
        packet.buffer.writeUInt64(updateData.ptr);
    }

    public getUniqueIdentifier(update: MakeCodeSyncUpdate) {
        return {
            ptr: update.ptr,
        }
    }

    public updateToString(updateData: any): string {
        return null;
    }
}