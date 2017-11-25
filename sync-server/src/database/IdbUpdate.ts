import { SyncType } from './../sync/ISyncHandler';
import { ObjectID } from 'mongodb';

export class IdbUpdate {
    public _id:ObjectID;

    public project_id:ObjectID;
    public user_id:ObjectID;

    public type:SyncType;
    public version:number;
}