import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export class Handshake extends BasePacket {
    public user_guid:string;
    public user_name:string;

    public binary_md5:string;
    public binary_name:string;
    public binary_version:number;

    public constructor() {
        super();

        this.packetType = PacketType.Handshake;
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.user_guid = buffer.readCharArray(38);
        this.user_name = buffer.readString();

        this.binary_md5 = buffer.readCharArray(16);
        this.binary_name = buffer.readString();
        this.binary_version = buffer.readUInt32();
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeCharArray(this.user_guid, 38);
        buffer.writeString(this.user_name);

        buffer.writeCharArray(this.binary_md5, 16);
        buffer.writeString(this.binary_name);
        buffer.writeUInt32(this.binary_version);
    }
}

export class HandshakeResponse extends BasePacket {
    public username:string;
    public project_name:string;

    public constructor() {
        super();

        this.packetType = PacketType.HandshakeResponse;
        this.packetSize = BasePacket.HEADER_SIZE + 96;
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.username = buffer.readCharArray(32);
        this.project_name = buffer.readCharArray(64);
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeCharArray(this.username, 32);
        buffer.writeCharArray(this.project_name, 64);
    }
}