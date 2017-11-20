import { PacketType } from './PacketType';

export class BasePacket {
    public static HEADER_SIZE = 4;

    public packetType:PacketType;
    public packetSize:number;

    public decode(buffer:Buffer) {};
}