//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A codec for framing SSH Agent protocol messages.
///
/// The SSH Agent protocol uses length-prefixed framing to encode messages.
/// Each message is prefixed with a 32-bit unsigned integer (big-endian) indicating
/// the length of the message that follows.
///
/// ## Message Format
///
/// ```
/// [messageLength:uint32][messageType:byte][messageContent:byte[messageLength-1]]
/// ```
///
/// This codec only handles the length prefix. The message type and content are
/// handled by ``NIOSSHAgentClientHandler`` and the protocol message encodings.
///
/// ## Usage
///
/// This type implements both `MessageToByteEncoder` and `ByteToMessageDecoder`,
/// so it should be used with NIO's `MessageToByteHandler` and `ByteToMessageHandler`:
///
/// ```swift
/// channel.pipeline.addHandlers([
///     MessageToByteHandler(SshAgentFrameCoder()),
///     ByteToMessageHandler(SshAgentFrameCoder())
/// ])
/// ```
public struct SshAgentFrameCoder {
    /// Create a new SSH Agent frame codec.
    public init() {}

}

extension SshAgentFrameCoder: Sendable {}

extension SshAgentFrameCoder: MessageToByteEncoder {
    public func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        try out.writeLengthPrefixed(as: UInt32.self) { buffer in
            buffer.writeBytes(data.readableBytesView)
        }
    }
}

extension SshAgentFrameCoder: ByteToMessageDecoder {
    public typealias InboundOut = ByteBuffer
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let len = buffer.getInteger(at: buffer.readerIndex, endianness: .big, as: UInt32.self)
        else {
            return .needMoreData
        }
        if buffer.readableBytes - 4 >= len {
            buffer.moveReaderIndex(forwardBy: 4)
            guard let slice = buffer.readSlice(length: Int(len)) else {
                throw NIOSSHAgentError.badResponse
            }
            context.fireChannelRead(wrapInboundOut(slice))
            return .continue
        }
        return .needMoreData
    }
}
