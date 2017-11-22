"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class BaseCollectionManager {
    initialize(db) {
        this.db = db;
        return new Promise((resolve, reject) => this.db.createCollection(this.collectionName).then(collection => {
            this.collection = collection;
            resolve(collection);
        })
            .catch(reject));
    }
}
exports.BaseCollectionManager = BaseCollectionManager;
//# sourceMappingURL=BaseCollectionManager.js.map