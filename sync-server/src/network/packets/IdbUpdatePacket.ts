import { SyncType } from './../../sync/ISyncHandler';
import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';
import { IdbUpdate } from './../../database/IdbUpdate';

export class IdbUpdatePacket extends BasePacket {
    public binaryVersion:number;
    public syncType:SyncType;

    public constructor() {
        super();

        this.packetType = PacketType.IdbUpdate;
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt32(this.binaryVersion);
        buffer.writeUInt16(this.syncType);
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.binaryVersion = buffer.readUInt32();
        this.syncType = buffer.readUInt16();
    }
}