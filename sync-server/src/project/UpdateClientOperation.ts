import { NetworkClient } from "../network/NetworkClient";
import { database, syncManager, server } from "../app";
import { ProjectData } from "../database/ProjectData";
import { IdbUpdate } from "../database/IdbUpdate";
import { setInterval, clearInterval } from "timers";
import { UpdateOperationStartPacket, UpdateOperationStopPacket, UpdateOperationProgressPacket } from "../network/packets/UpdateOperationPackets";

const UPDATE_BURST_INTERVAL = 75;
const UPDATE_BURST_SIZE = 1;

export class UpdateClientOperation {
    private project: ProjectData;
    private updates: IdbUpdate[] = [];
    private numTotalUpdates: number = 0;
    private timer: NodeJS.Timer = null;

    public constructor(private client: NetworkClient) {
        this.project = this.client.activeProject.data;
    }

    public start(localVersion: number) {
        console.log("[UpdateClientOperation] Client " + this.client.name + " needs " + (this.project.binaryVersion - localVersion) + " updates");

        // Find updates to sync
        database.idbUpdates.findUpdates(this.client.activeProject.data._id, localVersion, this.project.binaryVersion, true)
            .then(this.startInternal.bind(this))
    }

    private startInternal(updates: IdbUpdate[]) {
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
        let syncUpdates = this.updates.splice(0, UPDATE_BURST_SIZE);
        syncUpdates.forEach(update => this.client.activeProject.sendUpdate(update, this.client));

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
        const packet = new UpdateOperationStopPacket();
        server.sendPacket(this.client, packet);
    }
}