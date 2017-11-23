import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';
import { IdbUpdate, IdbUpdateType } from './../../database/IdbUpdate';

export class BaseIdbUpdatePacket extends BasePacket {
    public binaryVersion:number;

    public constructor() {
        super();

        this.packetSize += 4;
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt32(this.binaryVersion);
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.binaryVersion = buffer.readUInt32();
    }

    public toIdbUpdate():IdbUpdate {
        return null;
    }
}