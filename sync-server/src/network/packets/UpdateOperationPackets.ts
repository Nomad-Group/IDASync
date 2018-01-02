import { BasePacket } from "./BasePacket";
import { PacketType } from "./PacketType";
import { NetworkBuffer } from "../NetworkBuffer";


export class UpdateOperationStartPacket extends BasePacket {
    public numUpdates: number;

    public constructor() {
        super();

        this.packetType = PacketType.UpdateOperationStart;
    }

    public encode(buffer: NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt32(this.numUpdates);
    }

    public decode(buffer: NetworkBuffer) {
        super.decode(buffer);

        this.numUpdates = buffer.readUInt32();
    }
}

export class UpdateOperationProgressPacket extends BasePacket {
    public numUpdatesSynced: number;

    public constructor() {
        super();

        this.packetType = PacketType.UpdateOperationProgress;
    }

    public encode(buffer: NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt32(this.numUpdatesSynced);
    }

    public decode(buffer: NetworkBuffer) {
        super.decode(buffer);

        this.numUpdatesSynced = buffer.readUInt32();
    }
}

export class UpdateOperationStopPacket extends BasePacket {
    public constructor() {
        super();

        this.packetType = PacketType.UpdateOperationStop;
    }
}