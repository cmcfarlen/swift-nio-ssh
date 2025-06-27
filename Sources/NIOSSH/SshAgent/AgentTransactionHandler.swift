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

import NIO

/// SSH Agent specific error type
///
/// The follows the pattern of NIOSSHError, but for ssh agent errors
public struct NIOSSHAgentError: Error {
    public struct ErrorType {
        private enum Base {
            case agentNotAvailable
            case operationInProgress
        }
        private var base: Base

        private init(_ base: Base) {
            self.base = base
        }

        public static let agentNotAvailable: ErrorType = .init(.agentNotAvailable)
        public static let operationInProgress: ErrorType = .init(.operationInProgress)
    }

    public var type: ErrorType
    public var diagnostics: String?

    internal static func agentNotAvailable(reason: String) -> NIOSSHAgentError {
        NIOSSHAgentError(type: .agentNotAvailable, diagnostics: reason)
    }
    internal static let operationInProgress = NIOSSHAgentError(type: .operationInProgress, diagnostics: nil)
}

extension NIOSSHAgentError: CustomStringConvertible {
    public var description: String {
        "NIOSSHAgentError.\(self.type.description)\(self.diagnostics.map { ": \($0)" } ?? "")"
    }
}

extension NIOSSHAgentError.ErrorType: Hashable {}

extension NIOSSHAgentError.ErrorType: Sendable {}

extension NIOSSHAgentError.ErrorType: CustomStringConvertible {
    public var description: String {
        String(describing: self.base)
    }
}

public struct SshAgentTransaction: Sendable {
    let request: SshAgentRequest
    let promise: EventLoopPromise<SshAgentResponse>

    public init(request: SshAgentRequest, promise: EventLoopPromise<SshAgentResponse>) {
        self.request = request
        self.promise = promise
    }
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

    private enum State: ~Copyable {
        case idle
        case pending(SshAgentTransaction)

        mutating func nextTransaction(_ txn: SshAgentTransaction) -> Bool {
            switch consume self {
            case .idle:
                self = .pending(txn)
                return true
            case .pending(let currenttxn):
                self = .pending(currenttxn)
                return false
            }
        }

        mutating func succeed(_ response: SshAgentResponse) {
            switch consume self {
            case .idle:
                // This drops the response, but likely a logic error
                // can't seem to use precondition to check for an enum case
                fatalError("Inappropriate state for succeed call")
            case .pending(let currenttxn):
                currenttxn.promise.succeed(response)
                self = .idle
            }
        }

        mutating func fail(_ error: any Error) {
            switch consume self {
            case .idle:
                // This drops the response, but likely a logic error
                self = .idle
            case .pending(let currenttxn):
                currenttxn.promise.fail(error)
                self = .idle
            }
        }
    }

    private var state = State.idle

    public init() {}

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = self.unwrapInboundIn(data)

        state.succeed(response)
    }

    public func channelInactive(context: ChannelHandlerContext) {
        state.fail(NIOSSHAgentError.agentNotAvailable(reason: "Channel Inactive"))
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let transaction = unwrapOutboundIn(data)

        if state.nextTransaction(transaction) {
            _ = context.writeAndFlush(wrapOutboundOut(transaction.request))
        } else {
            transaction.promise.fail(NIOSSHAgentError.operationInProgress)
        }
    }
}

@available(*, unavailable)
extension NIOSSHAgentClientTransactionHandler: Sendable {}
