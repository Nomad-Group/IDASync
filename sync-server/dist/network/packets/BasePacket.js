"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class BasePacket {
    constructor() {
        this.packetSize = BasePacket.HEADER_SIZE;
    }
    decode(buffer) {
        this.packetType = buffer.readUInt16();
        this.packetSize = buffer.readUInt16();
    }
    encode(buffer) {
        buffer.writeUInt16(this.packetType);
        buffer.writeUInt16(this.packetSize);
    }
}
BasePacket.HEADER_SIZE = 4;
exports.BasePacket = BasePacket;
//# sourceMappingURL=BasePacket.js.map