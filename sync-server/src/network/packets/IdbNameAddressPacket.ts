import { IdbUpdateName } from './../../database/idb/IdbUpdateName';
import { IdbUpdate, IdbUpdateType } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BaseIdbUpdatePacket } from './BaseIdbUpdatePacket';

export class IdbNameAddressPacket extends BaseIdbUpdatePacket {
    public ptr:number;
    public name:string;

    public constructor() {
        super();

        this.packetType = PacketType.IdbNameAddressPacket;
        this.packetSize += 136;
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt64(this.ptr);
        buffer.writeCharArray(this.name, 128);
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.ptr = buffer.readUInt64();
        this.name = buffer.readCharArray(128);
    }

    public toIdbUpdate():IdbUpdate {
        var update = new IdbUpdateName();
        update.type = IdbUpdateType.Name;

        update.ptr = this.ptr;
        update.name = this.name;

        return update;
    }
}