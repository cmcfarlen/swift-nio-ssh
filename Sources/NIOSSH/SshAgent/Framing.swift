//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// SSH Agent protocol encodes integers in big endian
/// This struct is only used to write the the length prefix for messages
struct SshAgentBinaryIntegerEncodingStrategy: NIOBinaryIntegerEncodingStrategy {
    func readInteger<IntegerType>(
        as type: IntegerType.Type,
        from buffer: inout ByteBuffer
    )
        -> IntegerType? where IntegerType: FixedWidthInteger
    {
        guard let length = buffer.getInteger(at: buffer.readerIndex, endianness: .big, as: UInt32.self)
        else {
            return nil
        }
        buffer.moveReaderIndex(forwardBy: 4)
        return IntegerType(length)
    }

    func writeInteger<IntegerType>(_ integer: IntegerType, to buffer: inout ByteBuffer) -> Int
    where IntegerType: FixedWidthInteger {
        let length = UInt32(truncatingIfNeeded: integer)
        return buffer.writeInteger(length, endianness: .big)
    }

    var requiredBytesHint: Int { 4 }
}

extension NIOBinaryIntegerEncodingStrategy where Self == SshAgentBinaryIntegerEncodingStrategy {
    static var sshAgent: SshAgentBinaryIntegerEncodingStrategy {
        SshAgentBinaryIntegerEncodingStrategy()
    }
}

/// The SshAgent protocol uses a length-prefixed framing to encode messages
/// The format is:
///    [messageLength:uint32][messageType:byte][messageContent:byte[messageLength-1]]
///
public struct SshAgentFrameCoder {
    public init() {}

}

extension SshAgentFrameCoder: Sendable {}

extension SshAgentFrameCoder: MessageToByteEncoder {
    public func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        out.writeLengthPrefixed(strategy: .sshAgent) { buffer in
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
