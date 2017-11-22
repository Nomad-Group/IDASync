import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';

export class BasePacket {
    public static HEADER_SIZE = 4;
    public constructor() {
        this.packetSize = BasePacket.HEADER_SIZE;
    }

    public packetType:PacketType;
    public packetSize:number;

    public decode(buffer:NetworkBuffer) {
        this.packetType = buffer.readUInt16();
        this.packetSize = buffer.readUInt16();
    }

    public encode(buffer:NetworkBuffer) {
        buffer.writeUInt16(this.packetType);
        buffer.writeUInt16(this.packetSize);
    }
}