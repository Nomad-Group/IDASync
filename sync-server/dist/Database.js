"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mongodb_1 = require("mongodb");
const ProjectsManager_1 = require("./database/ProjectsManager");
class Database {
    constructor() {
        this.client = new mongodb_1.MongoClient();
        this.projects = new ProjectsManager_1.ProjectsManager();
    }
    initialize() {
        return new Promise((resolve, reject) => {
            this.client.connect("mongodb://localhost:27017/ida-synced")
                .then(this.initializeCollections.bind(this))
                .then(() => resolve());
        });
    }
    initializeCollections(db) {
        this.db = db;
        var manager = [
            this.projects.initialize(db)
        ];
        return Promise.all(manager);
    }
    close() {
        if (this.db) {
            this.db.close();
            this.db = null;
        }
    }
}
exports.Database = Database;
//# sourceMappingURL=Database.js.map