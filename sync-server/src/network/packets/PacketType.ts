export enum PacketType {
    Handshake = 0,
    HandshakeResponse,

    Heartbeat,
    BroadcastMessage,

    IdbUpdate,
    IdbUpdateResponse,

    // Update Operation
    UpdateOperationStart = 1000,
    UpdateOperationProgress,
    UpdateOperationStop
}