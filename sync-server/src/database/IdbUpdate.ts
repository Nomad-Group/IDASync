import { SyncType } from './../sync/ISyncHandler';
import { ObjectID } from 'mongodb';

export class IdbUpdate {
    public _id:ObjectID;

    public projectId:ObjectID;
    public userId:ObjectID;

    public type:SyncType;
    public version:number;
}