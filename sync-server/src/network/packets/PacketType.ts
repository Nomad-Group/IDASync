export enum PacketType {
    Handshake = 0,
    HandshakeResponse,

    Heartbeat,
    BroadcastMessage,

    IdbNameAddressPacket
}