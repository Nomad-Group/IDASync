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

    public check() {
        var collection: Collection = <Collection>this.collection;

        let x = collection.aggregate([
            {
                "$match": {
                    type: {
                        $in: [SyncType.AddReference, SyncType.DeleteReference]
                    },

                    shouldSync: true
                },
            },
            {
                "$group": {
                    "_id": {
                        ptrFrom: "$ptrFrom",
                        ptrTo: "$ptrTo",
                        referenceType: "$referenceType"
                    },
                    "ids": {
                        "$addToSet": {
                            _id: "$_id",
                            type: "$type"
                        }
                    }
                }
            }
        ]).toArray().then(res => {
            res.forEach(data => {

            })
        }).catch(err => {
            console.error(err);
        })
    }

    public findUpdates(projectId: ObjectID, fromVersion: number, toVersion?: number) {
        var query: any = { projectId: projectId };
        if (!toVersion) {
            query.version = fromVersion;
        } else {
            query.version = { $gt: fromVersion, $lte: toVersion };
        }

        return this.collection.find<IdbUpdate>(query).toArray();
    }

    public find(query) {
        return this.collection.find<IdbUpdate>(query).toArray();
    }

    public countForStats() {
        return this.collection.aggregate([
            {
                "$group": {
                    "_id": "$userId",
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