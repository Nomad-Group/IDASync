"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class PacketBuffer {
    constructor(buffer) {
        this.buffer = buffer;
        this.offset = 0;
    }
    readUInt8() {
        var result = this.buffer.readUInt8(this.offset);
        this.offset += 1;
        return result;
    }
    readUInt16() {
        var result = this.buffer.readUInt16LE(this.offset);
        this.offset += 2;
        return result;
    }
    readCharArray(size) {
        var result = this.buffer.toString("utf8", this.offset, this.offset + size);
        if (result.indexOf('\u0000') > -1)
            result.slice(0, result.indexOf('\u0000'));
        this.offset += size;
        return result;
    }
}
exports.PacketBuffer = PacketBuffer;
//# sourceMappingURL=PacketBuffer.js.map