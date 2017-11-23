
export class NetworkBuffer {
    public offset:number = 0;
    public constructor(public buffer:Buffer) {}

    public readUInt8():number {
        var result = this.buffer.readUInt8(this.offset);
        this.offset += 1;
        return result;
    }
    public writeUInt8(num) {
        this.buffer.writeUInt8(num, this.offset);
        this.offset++;
    }

    public readUInt16():number {
        var result = this.buffer.readUInt16LE(this.offset);
        this.offset += 2;
        return result;
    }
    public writeUInt16(num:number) {
        this.buffer.writeUInt16LE(num, this.offset);
        this.offset += 2;
    }

    public readUInt32():number {
        var result = this.buffer.readUInt32LE(this.offset);
        this.offset += 4;
        return result;
    }
    public writeUInt32(num:number) {
        this.buffer.writeUInt32LE(num, this.offset);
        this.offset += 4;
    }

    public readUInt64():number {
        return (this.readUInt32() << 8) + this.readUInt32();
    }
    public writeUInt64(num:number) {
        this.writeUInt32(num >> 8);
        this.writeUInt32(num & 0x00ff);
    }

    public readCharArray(size:number):string {
        var result = this.buffer.toString("utf8", this.offset, this.offset + size);
        if(result.indexOf('\u0000') > -1)
            result = result.slice(0, result.indexOf('\u0000'));
        this.offset += size;
        return result;
    }
    public writeCharArray(str:string, size:number) {
        if(str == null || str == undefined) {
            for(var i = 0; i < size; i++) {
                this.buffer[this.offset + i] = 0;
            }

            this.offset += size;
            return;
        }

        this.buffer.write(str, this.offset, str.length);
        for(var i = str.length; i < size; i++) {
            this.buffer[this.offset + i] = 0;
        }

        this.offset += size;
    }

    public writeString(str:string) {
        return this.writeCharArray(str, str.length);
    }
}