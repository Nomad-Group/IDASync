import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export class Heartbeat extends BasePacket {
    public constructor() {
        super();

        this.packetType = PacketType.Heartbeat;
    }
}