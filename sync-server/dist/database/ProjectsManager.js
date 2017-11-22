"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const BaseCollectionManager_1 = require("./BaseCollectionManager");
class ProjectsManager extends BaseCollectionManager_1.BaseCollectionManager {
    constructor() {
        super();
        this.collectionName = "projects";
    }
    findByMd5(md5_hash) {
        var query = { binary_md5: md5_hash };
        return this.collection.findOne(query);
    }
}
exports.ProjectsManager = ProjectsManager;
//# sourceMappingURL=ProjectsManager.js.map