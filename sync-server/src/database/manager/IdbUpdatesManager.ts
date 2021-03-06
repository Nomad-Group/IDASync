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

    public find(query): Promise<IdbUpdate[]> {
        return this.collection.find<IdbUpdate>(query).toArray();
    }

    public countForStats() {
        return new Promise<any>((resolve, reject) => {
            let promises: any = [];

            // User Updates
            promises.push(this.collection.aggregate([
                {
                    "$group": {
                        "_id": {
                            "userId": "$userId",
                            "projectId": "$projectId"
                        },
                        "count": {
                            "$sum": 1
                        }
                    }
                },
                {
                    "$sort": {
                        "count": -1
                    }
                }
            ]).toArray());

            // Updates
            promises.push(this.collection.aggregate([
                {
                    "$group": {
                        "_id": {
                            "type": "$type"
                        },
                        "count": {
                            "$sum": 1
                        }
                    }
                },
                {
                    "$sort": {
                        "count": -1
                    }
                }
            ]).toArray());

            // Promise
            Promise.all(promises)
                .then((results) => resolve({ userProjects: results[0], updates: results[1] }))
                .catch((err) => reject(err))
        })
    }

    public update(update: IdbUpdate) {
        return this.collection.updateOne({ _id: update._id }, update);
    }
}