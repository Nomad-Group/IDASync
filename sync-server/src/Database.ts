import { IdbUpdatesManager } from './database/manager/IdbUpdatesManager';
import { UserManager } from './database/manager/UserManager';
import { ProjectDataManager } from './database/manager/ProjectDataManager';
import { MongoClient, Db, Collection } from "mongodb";

export class Database {
    private client: MongoClient;
    private db: Db;

    public projects: ProjectDataManager;
    public idbUpdates: IdbUpdatesManager;
    public users: UserManager;

    public constructor() {
        this.client = new MongoClient();

        this.projects = new ProjectDataManager();
        this.idbUpdates = new IdbUpdatesManager();
        this.users = new UserManager();
    }

    public initialize(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            this.client.connect("mongodb://localhost:27017/ida-synced")
                .then(this.initializeCollections.bind(this))
                .then(() => resolve())
                .catch(reject)
        })
    }

    private initializeCollections(db: Db) {
        this.db = db;

        var manager = [
            this.projects.initialize(db),
            this.idbUpdates.initialize(db),
            this.users.initialize(db)
        ];
        return Promise.all(manager);
    }

    public close() {
        if (this.db) {
            this.db.close();
            this.db = null;
        }
    }
}