import { Long } from 'mongodb';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { ISyncHandler, SyncType } from './../ISyncHandler';
import { IdbUpdate } from './../../database/IdbUpdate';

export class ItemCommentSyncUpdateData extends IdbUpdate {
    public ptr: Long;
    public repeatable: boolean;
    public text: string;
}

export class ItemCommentSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.ItemComment;

    public decodePacket(updateData: ItemCommentSyncUpdateData, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
        updateData.repeatable = packet.buffer.readBoolean();
        updateData.text = packet.buffer.readString();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: ItemCommentSyncUpdateData) {
        packet.buffer.writeUInt64(updateData.ptr);
        packet.buffer.writeBoolean(updateData.repeatable);
        packet.buffer.writeString(updateData.text);
    }

    public getUniqueIdentifier(update: ItemCommentSyncUpdateData) {
        return {
            ptr: update.ptr
        }
    }

    public updateToString(updateData: any): string {
        return "added comment at " + updateData.ptr.toString(16) + ": " + updateData.text;
    }
}