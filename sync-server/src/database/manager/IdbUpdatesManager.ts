import { IdbUpdate } from './../IdbUpdate';
import { ProjectData } from './../ProjectData';

import { BaseCollectionManager } from './BaseCollectionManager';
import { Collection, ObjectID } from 'mongodb';
import { Db } from 'mongodb';
import { SyncType } from '../../sync/ISyncHandler';

export class IdbUpdatesManager extends BaseCollectionManager {
    public constructor() {
        super();

        this.collectionName = "idb_updates";
    }

    public create(update: IdbUpdate) {
        return new Promise<ObjectID>((resolve, reject) =>
            this.collection.insertOne(update)
                .then(result => resolve(result.insertedId))
                .catch(reason => reject(reason))
        );
    }

    public findUpdates(projectId: ObjectID, fromVersion: number, toVersion?: number, shouldSyncTrueOnly: boolean = false) {
        var query: any = { projectId: projectId };
        if (!toVersion) {
            query.version = fromVersion;
        } else {
            query.version = { $gt: fromVersion, $lte: toVersion };
        }
        if (shouldSyncTrueOnly) {
            query.shouldSync = true;
        }

        return this.collection.find<IdbUpdate>(query).sort({ "version": 1 }).toArray();
    }

    public find(query) {
        return this.collection.find<IdbUpdate>(query).toArray();
    }

    public countForStats() {
        return this.collection.aggregate([
            {
                "$group": {
                    "_id": {
                        "userId:": "$userId",
                        "projectId": "$projectId"
                    },
                    "count": {
                        "$sum": 1
                    }
                }
            }
        ]).toArray();
    }

    public update(update: IdbUpdate) {
        return this.collection.updateOne({ _id: update._id }, update);
    }
}