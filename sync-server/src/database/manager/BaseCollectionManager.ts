import { Collection, Db } from 'mongodb';

export class BaseCollectionManager {
    public collectionName: string;

    protected db: Db;
    protected collection: Collection;

    public initialize(db: Db) {
        this.db = db;

        return new Promise<Collection>((resolve, reject) =>
            this.db.createCollection(this.collectionName).then(collection => {
                this.collection = collection;
                resolve(collection);
            })
                .catch(reject)
        );
    }
}