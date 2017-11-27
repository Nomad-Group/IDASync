import { SyncManager } from './sync/SyncManager';
import { ProjectsManager } from './project/ProjectsManager';
import { ProjectData } from './database/ProjectData';
import { Database } from './Database';
import { Server } from './server';

export const database:Database = new Database();
export const server:Server = new Server();

export const projectsManager:ProjectsManager = new ProjectsManager();
export const syncManager:SyncManager = new SyncManager();

database.initialize()
.then(() => {
    console.log("[Database] Connected!");

    server.startServer();
})
.catch(() => {
    console.log("Failed to connect to Database!");
})