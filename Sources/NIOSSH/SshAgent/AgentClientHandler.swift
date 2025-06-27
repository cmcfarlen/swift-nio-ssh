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

/// A `ChannelDuplexHandler` for converting SSH Agent requests and responses
/// to `ByteBuffer`.  This handler is stateless.
///
/// This handler doesn't deal with message framing, so this handler
/// needs support from `SshAgentFrameCoder` and NIO Byte<->Message handlers
/// to handle that aspect of the protocol.
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

        guard let response = NIOSSHAgentResponse(from: &byteBuffer) else {
            // Bad response from agent
            return
        }

        context.fireChannelRead(wrapInboundOut(response))
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
