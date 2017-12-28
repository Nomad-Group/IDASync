import { Project } from './../project/Project';
import { User } from './../database/User';
import * as net from 'net';

export enum NetworkClientDisconnectReason {
    Disconnected,
    KickTimeout,
    Error
}

export class AccumulatingBuffer {
    private buffer: Buffer = new Buffer(0);
    private accumulatingLength: number = 0;
    private packageLength: number = 0;

    public onData(incomingBuffer: Buffer): Buffer {
        // New Package?
        if (this.packageLength == 0) {
            this.packageLength = incomingBuffer.readUInt16LE(0);
            this.buffer = new Buffer(this.packageLength);
            this.accumulatingLength = 0;
        }

        let remainingLength = this.packageLength - this.accumulatingLength;
        incomingBuffer.copy(this.buffer, this.accumulatingLength, 0, Math.min(incomingBuffer.length, remainingLength));
        this.accumulatingLength += incomingBuffer.length;

        if (this.accumulatingLength >= this.packageLength) {
            this.packageLength = 0;
            return Buffer.from(this.buffer);
        }

        return null;
    }
}

export class NetworkClient {
    public socket: net.Socket;
    public accumulatingBuffer: AccumulatingBuffer = new AccumulatingBuffer();
    public name: string;

    public user: User;
    public activeProject: Project;

    public lastHeartbeat: number = 0;
    public disconnectReason: NetworkClientDisconnectReason = NetworkClientDisconnectReason.Disconnected;
}