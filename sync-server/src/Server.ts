import { Heartbeat } from './packets/Heartbeat';
import { BasePacket } from './packets/BasePacket';
import { Handshake, HandshakeResponse } from './packets/Handshake';
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

    public constructor() {
        setInterval(this.onHeartbeat.bind(this), 1000);
    }

    private onHeartbeat() {
        var heartbeat = new Heartbeat();
        this.clients.forEach(client => this.sendPacket(client, heartbeat));
    }

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
        socket.on("close", this.onConnectionClosed.bind(this, client));
        socket.on("data", this.onClientData.bind(this, client));
        socket.on("error", this.onConnectionError.bind(this, client));
    }

    private onConnectionClosed(client:Client) {
        console.log("[Server] Client disconnected (" + client.name + ")");
        this.clients.splice(this.clients.indexOf(client));
    }

    private onConnectionError(client:Client, error:Error) {
        console.error("[Server] Client (" + client.name + ") caused error: " + error.name + "\n" + error.message);
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

        if(packet.packetType == PacketType.Handshake)
        {
            var response = new HandshakeResponse();
            response.username = "You suck";
            console.log(response);

            this.sendPacket(client, response);
            setTimeout(() => {
                this.sendPacket(client, response);
            }, 1000);
        }
    }

    public sendPacket(client:Client, packet:BasePacket) {
        var buffer:Buffer = new Buffer(packet.packetSize);
        packet.encode(buffer);

        client.socket.write(buffer);
        //client.socket.pipe(client.socket);
    }
}