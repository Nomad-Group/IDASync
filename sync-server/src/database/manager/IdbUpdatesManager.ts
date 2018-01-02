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
                            type: "$type",
                            version: "$version"
                        }
                    }
                }
            }
        ]).toArray().then(res => {
            let countDeactivate: number = 0;

            res.forEach(data => {
                let countDeactivateInitial: number = countDeactivate;
                let refAdd: any[] = [];
                let refDelete: any[] = [];

                data.ids.forEach(upd => {
                    if (upd.type == SyncType.AddReference) {
                        refAdd.push(upd);
                    } else {
                        refDelete.push(upd);
                    }
                });

                // Sortieren der Arrays
                let sortFunc = (a, b) => {
                    if (a.version < b.version) {
                        return 1;
                    }

                    if (a.version > b.version) {
                        return -1;
                    }

                    return 0;
                };

                refAdd.sort(sortFunc);
                refDelete.sort(sortFunc);

                // Alle die auf Add stehen entfernen, bis auf 1
                // das mit der neusten version darf bleiben
                let newestAdd = refAdd.splice(0, 1);
                /*this.collection.update(
                    {
                        _id: {
                            "$in": refAdd
                        }
                    },
                    {
                        shouldSync: false
                    });*/
                countDeactivate += refAdd.length;

                // Alle die auf Remove stehen entfernen, bis auf 1
                // das mit der neusten version darf bleiben
                let newestDelete = refDelete.splice(0, 1);
                /*this.collection.update(
                    {
                        _id: {
                            "$in": refDelete
                        }
                    },
                    {
                        shouldSync: false
                    });*/
                countDeactivate += refDelete.length;

                // Logik
                if (newestAdd.length == 1 && newestDelete.length == 0) {
                    // alles richtig
                    // die ref ist aktiv und in ordnung
                }
                if (newestAdd.length == 1 && newestDelete.length == 1) {
                    // nicht mehr aktiv, also muss add nicht mehr gesynced werden
                    // delete muss gesynced werden für neue clients
                    /*this.collection.update(
                        {
                            _id: newestAdd[0]._id
                        },
                        {
                            shouldSync: false
                        });*/
                    countDeactivate++;
                }

                console.log(
                    "add: " + (refAdd.length + newestAdd.length) +
                    ", del: " + (refDelete.length + newestDelete.length) +
                    ", deactivate: " + (countDeactivate - countDeactivateInitial)
                );
            })

            console.log("TOTAL DEACTIVATE: " + countDeactivate);
        }).catch(err => {
            console.error(err);
        })
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