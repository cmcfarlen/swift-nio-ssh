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

import NIO

public enum SshAgentError: Error {
    case agentNotAvailable(reason: String)
    case operationInProgress
}

public struct SshAgentTransaction: Sendable {
    let request: SshAgentRequest
    let promise: EventLoopPromise<SshAgentResponse>
}

/// SSH Agent transactor
///
/// This handler keeps one pending transaction and will reject any others
/// that come in before the pending one completes
public final class NIOSSHAgentClientTransactionHandler: ChannelDuplexHandler {
    public typealias InboundIn = SshAgentResponse
    public typealias InboundOut = SshAgentResponse
    public typealias OutboundIn = SshAgentTransaction
    public typealias OutboundOut = SshAgentRequest

    var pending: SshAgentTransaction? = nil

    public init() {}

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = self.unwrapInboundIn(data)

        guard let pending else {
            // unexpected response
            return
        }

        pending.promise.succeed(response)
        self.pending = nil
    }

    public func channelInactive(context: ChannelHandlerContext) {
        if let pending {
            pending.promise.fail(SshAgentError.agentNotAvailable(reason: "Channel inactive"))
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let transaction = unwrapOutboundIn(data)

        if pending == nil {
            pending = transaction
            _ = context.writeAndFlush(wrapOutboundOut(transaction.request))
        } else {
            transaction.promise.fail(SshAgentError.operationInProgress)
        }
    }
}
