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

/// A `ChannelDuplexHandler` for converting SSH Agent requests and responses to and from `ByteBuffer`.
///
/// This handler is stateless and performs the encoding and decoding of SSH Agent protocol messages.
/// It converts:
/// - Outbound ``NIOSSHAgentRequest`` values into `ByteBuffer` containing the wire protocol format
/// - Inbound `ByteBuffer` values (wire protocol) into ``NIOSSHAgentResponse`` values
///
/// This handler does not handle message framing. It must be used in conjunction with ``SshAgentFrameCoder``
/// and NIO's `ByteToMessageHandler` and `MessageToByteHandler` to manage the length-prefixed framing
/// required by the SSH Agent protocol.
///
/// ## Typical Pipeline Setup
///
/// ```swift
/// channel.pipeline.addHandlers([
///     MessageToByteHandler(SshAgentFrameCoder()),
///     ByteToMessageHandler(SshAgentFrameCoder()),
///     NIOSSHAgentClientHandler(),
///     NIOSSHAgentClientTransactionHandler()
/// ])
/// ```
public final class NIOSSHAgentClientHandler: ChannelDuplexHandler {
    // These ByteBuffers will just be the message type and payload
    // The length is trimmed off/added by framing handlers
    public typealias InboundIn = ByteBuffer  // ssh-agent wire responses
    public typealias InboundOut = NIOSSHAgentResponse
    public typealias OutboundIn = NIOSSHAgentRequest
    public typealias OutboundOut = ByteBuffer  // ssh-agent wire requests

    public init() {}

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var byteBuffer = self.unwrapInboundIn(data)

        do {
            let response = try byteBuffer.readSSHAgentResponse()

            context.fireChannelRead(wrapInboundOut(response))
        } catch {
            context.fireErrorCaught(error)
        }
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Close the connection on error
        context.close(promise: nil)
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let request = unwrapOutboundIn(data)

        var buffer = context.channel.allocator.buffer(capacity: 32)

        request.encode(into: &buffer)

        context.write(wrapOutboundOut(buffer), promise: promise)
    }
}

extension NIOSSHAgentClientHandler: Sendable {}
