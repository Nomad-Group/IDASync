"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class NetworkBuffer {
    constructor(buffer) {
        this.buffer = buffer;
        this.offset = 0;
    }
    readUInt8() {
        var result = this.buffer.readUInt8(this.offset);
        this.offset += 1;
        return result;
    }
    writeUInt8(num) {
        this.buffer.writeUInt8(num, this.offset);
        this.offset++;
    }
    readUInt16() {
        var result = this.buffer.readUInt16LE(this.offset);
        this.offset += 2;
        return result;
    }
    writeUInt16(num) {
        this.buffer.writeUInt16LE(num, this.offset);
        this.offset += 2;
    }
    readCharArray(size) {
        var result = this.buffer.toString("utf8", this.offset, this.offset + size);
        if (result.indexOf('\u0000') > -1)
            result.slice(0, result.indexOf('\u0000'));
        this.offset += size;
        return result;
    }
    writeCharArray(str, size) {
        if (str == null || str == undefined) {
            for (var i = 0; i < size; i++) {
                this.buffer[this.offset + i] = 0;
            }
            this.offset += size;
            return;
        }
        this.buffer.write(str, this.offset, str.length);
        for (var i = str.length; i < size; i++) {
            this.buffer[this.offset + i] = 0;
        }
        this.offset += size;
    }
    writeString(str) {
        return this.writeCharArray(str, str.length);
    }
}
exports.NetworkBuffer = NetworkBuffer;
//# sourceMappingURL=NetworkBuffer.js.map