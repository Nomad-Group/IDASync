import { BasePacket } from './packets/BasePacket';
import { Long } from 'mongodb';

export class NetworkBuffer {
    public offset: number = 0;

    public constructor(public buffer: Buffer = new Buffer(BasePacket.HEADER_SIZE)) { }

    public resize(newSize: number) {
        if (this.buffer.length == newSize) {
            return this.buffer.length;
        }

        var oldSize = this.buffer.length;

        // Buffer
        var newBuffer = new Buffer(newSize);
        this.buffer.copy(newBuffer);
        this.buffer = newBuffer;

        return oldSize;
    }

    public adjustSizeFor(size: number) {
        var requiredSize = this.offset + size;
        if (requiredSize > this.buffer.length) {
            this.resize(requiredSize);
        }
    }

    // adjustSizeFor + add to offset
    public reserve(size: number) {
        this.adjustSizeFor(size);
        this.offset += size;
    }

    public getSize(): number {
        // Hmmmm....
        return this.offset;
    }

    public readBoolean(): boolean {
        return this.readUInt8() == 1;
    }
    public writeBoolean(val: boolean) {
        this.writeUInt8(val == true ? 1 : 0);
    }

    public readUInt8(): number {
        var result = this.buffer.readUInt8(this.offset);
        this.offset += 1;
        return result;
    }
    public writeUInt8(num) {
        this.adjustSizeFor(1);

        this.buffer.writeUInt8(num, this.offset);
        this.offset++;
    }

    public readUInt16(): number {
        var result = this.buffer.readUInt16LE(this.offset);
        this.offset += 2;
        return result;
    }
    public writeUInt16(num: number) {
        this.adjustSizeFor(2);

        this.buffer.writeUInt16LE(num, this.offset);
        this.offset += 2;
    }

    public readInt32(): number {
        var result = this.buffer.readInt32LE(this.offset);
        this.offset += 4;
        return result;
    }
    public writeInt32(num: number) {
        this.adjustSizeFor(4);

        this.buffer.writeInt32LE(num, this.offset);
        this.offset += 4;
    }

    public readUInt32(): number {
        var result = this.buffer.readUInt32LE(this.offset, true);
        this.offset += 4;
        return result;
    }
    public writeUInt32(num: number) {
        this.adjustSizeFor(4);

        this.buffer.writeUInt32LE(num, this.offset, true);
        this.offset += 4;
    }

    public readInt64(): Long {
        return Long.fromBits(this.readInt32(), this.readInt32());
    }
    public writeInt64(num: Long) {
        if (typeof (num) != typeof (Long)) {
            num = Long.fromNumber(<any>num);
        }

        this.writeInt32(num.getLowBits());
        this.writeInt32(num.getHighBits());
    }

    public readUInt64(): Long {
        return Long.fromBits(this.readUInt32(), this.readUInt32());
    }
    public writeUInt64(num: Long) {
        if (typeof (num) != typeof (Long)) {
            num = Long.fromNumber(<any>num);
        }

        this.writeUInt32(num.getLowBitsUnsigned());
        this.writeUInt32(num.getHighBits());
    }

    public readCharArray(size: number): string {
        var result = this.buffer.toString("utf8", this.offset, this.offset + size);
        if (result.indexOf('\u0000') > -1)
            result = result.slice(0, result.indexOf('\u0000'));
        this.offset += size;
        return result;
    }
    public writeCharArray(str: string, size: number) {
        this.adjustSizeFor(size);

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

    public readString(): string {
        var size = 0;

        for (var i = 0; i < this.buffer.length; i++) {
            if (this.buffer[this.offset + i] == 0) {
                size = i;
                break;
            }
        }

        if (size == 0) {
            this.offset++;
            return null;
        }

        var result = this.buffer.toString("utf8", this.offset, this.offset + size);
        this.offset += size + 1;
        return result;
    }
    public writeString(str: string): number {
        if (str == null || str.length == 0) {
            this.writeUInt8(0);
            return 1;
        }

        this.writeCharArray(str, str.length);
        this.writeUInt8(0);

        return str.length + 1;
    }
}