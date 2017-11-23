import { IdbUpdateName } from './../../database/idb/IdbUpdateName';
import { IdbUpdate, IdbUpdateType } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BaseIdbUpdatePacket } from './BaseIdbUpdatePacket';

export class IdbNameAddressPacket extends BaseIdbUpdatePacket {
    public updateData:IdbUpdateName = new IdbUpdateName();

    public constructor() {
        super();

        this.packetType = PacketType.IdbNameAddressPacket;
        this.packetSize += 136;
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt32(this.updateData.version);
        buffer.writeUInt64(this.updateData.ptr);
        buffer.writeCharArray(this.updateData.name, 128);
        buffer.writeUInt8(this.updateData.local ? 1 : 0);
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.updateData.version = buffer.readUInt32();
        this.updateData.ptr = buffer.readUInt64();
        this.updateData.name = buffer.readCharArray(128);
        this.updateData.local = buffer.readUInt8() == 1;
    }

    public getUpdateData():IdbUpdate {
        return this.updateData;
    }
}