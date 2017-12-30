import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export class Handshake extends BasePacket {
    public userGuid: string;
    public userName: string;
    public clientVersion: number;

    public binaryMD5: string;
    public binaryName: string;
    public binaryVersion: number;

    public constructor() {
        super();

        this.packetType = PacketType.Handshake;
    }

    public decode(buffer: NetworkBuffer) {
        super.decode(buffer);

        this.userGuid = buffer.readCharArray(38);
        this.userName = buffer.readString();

        this.binaryMD5 = buffer.readCharArray(16);
        this.binaryName = buffer.readString();
        this.binaryVersion = buffer.readUInt32();

        this.clientVersion = buffer.readUInt8();
    }

    public encode(buffer: NetworkBuffer) {
        super.encode(buffer);

        buffer.writeCharArray(this.userGuid, 38);
        buffer.writeString(this.userName);

        buffer.writeCharArray(this.binaryMD5, 16);
        buffer.writeString(this.binaryName);
        buffer.writeUInt32(this.binaryVersion);

        buffer.writeUInt8(this.clientVersion);
    }
}

export class HandshakeResponse extends BasePacket {
    public username: string;
    public projectName: string;
    public projectVersion: number;

    public constructor() {
        super();

        this.packetType = PacketType.HandshakeResponse;
        this.packetSize = BasePacket.HEADER_SIZE + 96;
    }

    public decode(buffer: NetworkBuffer) {
        super.decode(buffer);

        this.username = buffer.readString();
        this.projectName = buffer.readString();
        this.projectVersion = buffer.readUInt32();
    }

    public encode(buffer: NetworkBuffer) {
        super.encode(buffer);

        buffer.writeString(this.username);
        buffer.writeString(this.projectName);
        buffer.writeUInt32(this.projectVersion);
    }
}