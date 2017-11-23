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

    public findUpdates(project_id:ObjectID, from_version:number, to_version?:number) {
        var query:any = { project_id: project_id };
        if(!to_version) {
            query.version = from_version;
        } else {
            query.version = { $gt: from_version, $lte: to_version };
        }

        return this.collection.find<IdbUpdate>(query).toArray();
    }
}