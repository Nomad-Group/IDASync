import { NetworkClient } from "../network/NetworkClient";
import { database, syncManager, server } from "../app";
import { ProjectData } from "../database/ProjectData";
import { IdbUpdate } from "../database/IdbUpdate";
import { setInterval, clearInterval } from "timers";
import { UpdateOperationStartPacket, UpdateOperationStopPacket, UpdateOperationProgressPacket, UpdateOperationUpdateBurstPacket } from "../network/packets/UpdateOperationPackets";
import { IdbUpdateResponsePacket } from "../network/packets/IdbUpdatePacket";

const UPDATE_BURST_INTERVAL = 75;
const UPDATE_BURST_SIZE = 5;

export class UpdateClientOperation {
    private project: ProjectData;
    private updates: IdbUpdate[] = [];
    private numTotalUpdates: number = 0;
    private timer: NodeJS.Timer = null;

    public constructor(private client: NetworkClient) {
        this.project = this.client.activeProject.data;
    }

    public start(localVersion: number) {
        // Find updates to sync
        database.idbUpdates.findUpdates(this.client.activeProject.data._id, localVersion, this.project.binaryVersion, true)
            .then(this.startInternal.bind(this))
    }

    private startInternal(updates: IdbUpdate[]) {
        console.log("[UpdateClientOperation] Client " + this.client.name + " needs " + updates.length + " updates");

        // Updates
        this.updates = updates;
        this.numTotalUpdates = this.updates.length;

        // Minimum
        if (this.numTotalUpdates < 3) {
            this.updates.forEach(update => this.client.activeProject.sendUpdate(update, this.client));
            this.updates = [];

            return;
        }

        // Start Operation
        const packet = new UpdateOperationStartPacket();
        packet.numUpdates = this.numTotalUpdates;
        server.sendPacket(this.client, packet);

        // Timer
        this.timer = setInterval(this.sendBurst.bind(this), UPDATE_BURST_INTERVAL);
        this.sendBurst(); // no time to lose!
    }

    private sendBurst() {
        // Update Burst
        let burstPacket = new UpdateOperationUpdateBurstPacket();

        let syncUpdates = this.updates.splice(0, UPDATE_BURST_SIZE);
        syncUpdates.forEach(update => {
            let updatePacket = syncManager.encodePacket(update);
            burstPacket.updates.push(updatePacket);
        });

        server.sendPacket(this.client, burstPacket, true);

        // Operation Progress
        const packet = new UpdateOperationProgressPacket();
        packet.numUpdatesSynced = this.numTotalUpdates - this.updates.length;
        server.sendPacket(this.client, packet);

        // Stop
        if (this.updates.length == 0) {
            console.log("[UpdateClientOperation] Client " + this.client.name + " finished!");
            this.stop();
        }
    }

    public stop() {
        // Timer
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }

        // Stop Operation
        if (!this.client.socket.destroyed) {
            const packet = new UpdateOperationStopPacket();
            packet.version = this.client.activeProject.data.binaryVersion;
            server.sendPacket(this.client, packet);
        }
    }
}