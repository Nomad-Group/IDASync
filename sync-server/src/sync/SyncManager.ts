import { ItemCommentSyncHandler } from './handler/ItemCommentSyncHandler';
import { NetworkBuffer } from './../network/NetworkBuffer';
import { IdbUpdate } from './../database/IdbUpdate';
import { IdbUpdatePacket } from './../network/packets/IdbUpdatePacket';
import { NameSyncHandler } from './handler/NameSyncHandler';
import { ISyncHandler, SyncType } from './ISyncHandler';

export class SyncManager {
    public syncHandlers: ISyncHandler[] = [
        new NameSyncHandler(),
        new ItemCommentSyncHandler()
    ];

    public decodePacket(packet: IdbUpdatePacket): IdbUpdate {
        if (packet.syncType >= this.syncHandlers.length) {
            return null;
        }

        // Update Data
        var updateData = new IdbUpdate();
        updateData.type = packet.syncType;

        // Decode Packet
        var syncHandler = this.syncHandlers[packet.syncType];
        syncHandler.decodePacket(updateData, packet);

        // Done
        return updateData;
    }

    public encodePacket(updateData: IdbUpdate): IdbUpdatePacket {
        // Update Packet
        var updatePacket = new IdbUpdatePacket();
        updatePacket.syncType = updateData.type;
        updatePacket.binaryVersion = updateData.version;

        // Encode Header
        updatePacket.buffer = new NetworkBuffer();
        updatePacket.encode(updatePacket.buffer);

        // Encode Body
        var syncHandler = this.syncHandlers[updateData.type];
        syncHandler.encodePacket(updatePacket, updateData);

        // Done
        return updatePacket;
    }
}