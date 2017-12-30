import { NetworkClientDisconnectReason } from './../network/NetworkClient';
import { server } from './../app';
import { Heartbeat } from './../network/packets/Heartbeat';

const HeartbeatInterval = 2500; // ms
const HeartbeatKickAfter = 5100; // ms

export class HeartbeatService {
    public constructor() {
        setInterval(this.onHeartbeat.bind(this), HeartbeatInterval);
    }

    private onHeartbeat() {
        // Check last Hearbeat on Clients
        server.clients.forEach(client => {
            if ((Date.now() - client.lastHeartbeat) > HeartbeatKickAfter && client.lastHeartbeat > 2) {
                client.disconnectReason = NetworkClientDisconnectReason.KickTimeout;
                client.socket.destroy();
                return;
            }

            // in case our client is a massive cunt and never responds to any heartbeats
            client.lastHeartbeat++;
        });

        // Send Heartbeat
        var heartbeat = new Heartbeat();
        heartbeat.timestamp = Date.now();

        server.sendPackets(server.clients, heartbeat);
    }
}