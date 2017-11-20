import { BasePacket } from './BasePacket';

export class Handshake extends BasePacket {
    public guid:string;

    public decode(buffer:Buffer) {
        this.guid = buffer.toString("utf8", BasePacket.HEADER_SIZE, BasePacket.HEADER_SIZE + 38);
    }
}