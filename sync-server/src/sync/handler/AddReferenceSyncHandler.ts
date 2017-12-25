import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export enum ReferenceType {
    Code = 0,
    Data = 1
}

class AddReferenceSyncUpdate extends IdbUpdate {
    public referenceType: ReferenceType;

    public ptrFrom: Long;
    public ptrTo: Long;
    public referenceDataType: number;
}

export class AddReferenceSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.AddReference;

    public decodePacket(updateData: AddReferenceSyncUpdate, packet: IdbUpdatePacket) {
        updateData.referenceType = packet.buffer.readUInt8();

        updateData.ptrFrom = packet.buffer.readUInt64();
        updateData.ptrTo = packet.buffer.readUInt64();
        updateData.referenceDataType = packet.buffer.readUInt32();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: AddReferenceSyncUpdate) {
        packet.buffer.writeUInt8(updateData.referenceType);

        packet.buffer.writeUInt64(updateData.ptrFrom);
        packet.buffer.writeUInt64(updateData.ptrTo);
        packet.buffer.writeUInt32(updateData.referenceDataType);
    }

    public getUniqueIdentifier(update: AddReferenceSyncUpdate) {
        return null;
    }

    public updateToString(updateData: any): string {
        return null;
    }
}