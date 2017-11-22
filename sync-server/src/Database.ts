import { MongoClient, Db, Collection } from "mongodb";
import { ProjectsManager } from "./database/ProjectsManager";

export class Database {
    private client:MongoClient;
    private db:Db;

    public projects:ProjectsManager;

    public constructor() {
        this.client = new MongoClient();
        this.projects = new ProjectsManager();
    }

    public initialize():Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.client.connect("mongodb://localhost:27017/ida-synced")
            .then(this.initializeCollections.bind(this))
            .then(() => resolve())
        })
    }

    private initializeCollections(db:Db) {
        this.db = db;

        var manager = [
            this.projects.initialize(db)
        ];
        return Promise.all(manager);
    }

    public close() {
        if(this.db) {
            this.db.close();
            this.db = null;
        }
    }
}