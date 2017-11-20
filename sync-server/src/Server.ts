import { BasePacket } from './packets/BasePacket';
import { Handshake } from './packets/Handshake';
import { PacketType } from './packets/PacketType';
import * as net from 'net';

class Client {
    public socket:net.Socket;
    public name:string;
}

export class Server {
    public static readonly PORT:number = 4523;
    public server:net.Server;
    private clients:Client[] = [];

    public startServer() {
        this.server = net.createServer(this.onConnection.bind(this)).listen(Server.PORT);
    }

    private onConnection(socket:net.Socket) {
        // Client
        var client = new Client();
        client.socket = socket;
        client.name = socket.remoteAddress + ":" + socket.remotePort;
        this.clients.push(client);

        // Log
        console.log("[Server] Client connected (" + client.name + ")");

        // Event Handler
        socket.on("end", this.onConnectionClosed.bind(this, client));
        socket.on("data", this.onClientData.bind(this, client));       
    }

    private onConnectionClosed(client:Client) {
        console.log("[Server] Client disconnected (" + client.name + ")");
    }

    private onClientData(client:Client, data:Buffer) {
        console.log("[Server] Data: " + data.toString());

        var packet:BasePacket = null;
        var packetType:PacketType = data.readUInt8(0);

        switch(packetType)
        {
            case PacketType.Handshake: {
                packet = new Handshake();
            }
        }

        if(packet == null) {
            console.log("[Server] ERROR: Client (" + client.name + ") sent unknown Packet Type " + packetType.toString());
            return;
        }

        // Packet Header
        packet.packetType = packetType;
        packet.packetSize = data.readUInt16LE(2);

        // Decode Packet
        packet.decode(data);

        // DEBUG
        console.log(packet);
    }
}