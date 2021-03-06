import { SyncManager } from './sync/SyncManager';
import { ProjectsManager } from './project/ProjectsManager';
import { ProjectData } from './database/ProjectData';
import { Database } from './Database';
import { Server } from './Server';
import { DiscordBot } from './DiscordBot';
import { PublicFeed } from './PublicFeed';

export const database: Database = new Database();
export const server: Server = new Server();

export const projectsManager: ProjectsManager = new ProjectsManager();
export const syncManager: SyncManager = new SyncManager();

export const discordBot: DiscordBot = new DiscordBot();
export const publicFeed: PublicFeed = new PublicFeed();

database.initialize()
    .then(() => {
        console.log("[Database] Connected!");

        server.startServer();
        discordBot.initialize();
    })
    .catch(() => {
        console.log("Failed to connect to Database!");
    })