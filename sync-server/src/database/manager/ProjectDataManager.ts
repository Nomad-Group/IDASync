import { ProjectData } from './../ProjectData';

import { BaseCollectionManager } from './BaseCollectionManager';
import { Collection, ObjectID } from 'mongodb';
import { Db } from 'mongodb';

export class ProjectDataManager extends BaseCollectionManager {
    public constructor() {
        super();

        this.collectionName = "projects";
    }

    public findByMd5(binaryMD5: string): Promise<ProjectData> {
        var query = { binaryMD5: binaryMD5 };
        return this.collection.findOne(query);
    }

    public find(query: any = {}): Promise<ProjectData[]> {
        return this.collection.find(query).toArray();
    }

    public create(project: ProjectData) {
        return new Promise<ObjectID>((resolve, reject) =>
            this.collection.insertOne(project)
                .then(result => resolve(result.insertedId))
                .catch(reason => reject(reason))
        );
    }

    public update(project: ProjectData) {
        return this.collection.updateOne({ _id: project._id }, project);
    }
}