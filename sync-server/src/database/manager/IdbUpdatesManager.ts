import { IdbUpdate } from './../IdbUpdate';
import { ProjectData } from './../ProjectData';

import { BaseCollectionManager } from './BaseCollectionManager';
import { Collection, ObjectID } from 'mongodb';
import { Db } from 'mongodb';

export class IdbUpdatesManager extends BaseCollectionManager {
    public constructor() {
        super();

        this.collectionName = "idb_updates";
    }

    public create(update:IdbUpdate) {
        return new Promise<ObjectID>((resolve, reject) =>
             this.collection.insertOne(update)
             .then(result => resolve(result.insertedId))
             .catch(reason => reject(reason))
        );
    }
}