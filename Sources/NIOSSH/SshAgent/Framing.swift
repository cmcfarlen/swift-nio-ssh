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

/// The SshAgent protocol uses a length-prefixed framing to encode messages
/// The format is:
///    [messageLength:uint32][messageType:byte][messageContent:byte[messageLength-1]]
///
/// The `SshAgentFrameCoder` only deals with adding the message length to the frames,
/// the rest of the frame is handled by the protocol message encodings.
///
public struct SshAgentFrameCoder {
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
            context.fireChannelRead(wrapInboundOut(buffer.readSlice(length: Int(len))!))
            return .continue
        }
        return .needMoreData
    }
}
