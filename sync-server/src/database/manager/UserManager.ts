import { User } from './../User';

import { BaseCollectionManager } from './BaseCollectionManager';
import { ObjectID } from 'mongodb';

export class UserManager extends BaseCollectionManager {
    public constructor() {
        super();

        this.collectionName = "users";
    }

    public findByHardwareId(hardware_id:string):Promise<User> {
        var query = { hardware_id: hardware_id };
        return this.collection.findOne(query);
    }

    public create(user:User) {
        return new Promise<ObjectID>((resolve, reject) =>
             this.collection.insertOne(user)
             .then(result => resolve(result.insertedId))
             .catch(reason => reject(reason))
        );
    }
}