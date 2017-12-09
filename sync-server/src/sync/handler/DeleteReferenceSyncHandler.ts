import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';
import { ReferenceType } from './AddReferenceSyncHandler'

class DeleteReferenceSyncUpdate extends IdbUpdate {
    public referenceType: ReferenceType;

    public ptrFrom: Long;
    public ptrTo: Long;

    public expand: boolean = undefined; // only for ReferenceType.Code
}

export class DeleteReferenceSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.DeleteReference;

    public decodePacket(updateData: DeleteReferenceSyncUpdate, packet: IdbUpdatePacket) {
        updateData.referenceType = packet.buffer.readUInt8();

        updateData.ptrFrom = packet.buffer.readUInt64();
        updateData.ptrTo = packet.buffer.readUInt64();

        if (updateData.referenceType == ReferenceType.Code) {
            updateData.expand = packet.buffer.readBoolean();
        }
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: DeleteReferenceSyncUpdate) {
        packet.buffer.writeUInt8(updateData.referenceType);

        packet.buffer.writeUInt64(updateData.ptrFrom);
        packet.buffer.writeUInt64(updateData.ptrTo);

        if (updateData.referenceType == ReferenceType.Code) {
            packet.buffer.writeBoolean(updateData.expand);
        }
    }

    public getUniqueIdentifier(update: DeleteReferenceSyncUpdate) {
        return null;
    }
}