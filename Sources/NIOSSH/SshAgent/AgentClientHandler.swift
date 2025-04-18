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

import Foundation
import NIO
import System

public final class NIOSSHAgentClientHandler: ChannelDuplexHandler {
    // These ByteBuffers will just be the message type and payload
    // The length is trimmed off/added by framing handlers
    public typealias InboundIn = ByteBuffer  // ssh-agent wire responses
    public typealias InboundOut = SshAgentResponse
    public typealias OutboundIn = SshAgentRequest
    public typealias OutboundOut = ByteBuffer  // ssh-agent wire requests

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var byteBuffer = self.unwrapInboundIn(data)

        guard let response = SshAgentResponse(from: &byteBuffer) else {
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

        promise?.succeed()

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }
}

extension NIOSSHAgentClientHandler: Sendable {}
