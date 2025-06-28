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
            case trailingBytes
            case badResponse
        }
        private var base: Base

        private init(_ base: Base) {
            self.base = base
        }

        public static let agentNotAvailable: ErrorType = .init(.agentNotAvailable)
        public static let operationInProgress: ErrorType = .init(.operationInProgress)
        public static let trailingBytes: ErrorType = .init(.trailingBytes)
        public static let badResponse: ErrorType = .init(.badResponse)
    }

    public var type: ErrorType
    public var diagnostics: String?

    internal static func agentNotAvailable(reason: String) -> NIOSSHAgentError {
        NIOSSHAgentError(type: .agentNotAvailable, diagnostics: reason)
    }
    internal static let operationInProgress = NIOSSHAgentError(type: .operationInProgress, diagnostics: nil)
    internal static let trailingBytes = NIOSSHAgentError(
        type: .trailingBytes,
        diagnostics: "Unexpected trailing bytes remaining after read"
    )
    internal static let badResponse = NIOSSHAgentError(
        type: .badResponse,
        diagnostics: "Recieved bad response from agent"
    )
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

public struct NIOSSHAgentTransaction: Sendable {
    public var request: NIOSSHAgentRequest
    public var promise: EventLoopPromise<NIOSSHAgentResponse>

    public init(request: NIOSSHAgentRequest, promise: EventLoopPromise<NIOSSHAgentResponse>) {
        self.request = request
        self.promise = promise
    }
}

/// SSH Agent transactor
///
/// This handler keeps one pending transaction and will reject any others
/// that come in before the pending one completes
public final class NIOSSHAgentClientTransactionHandler: ChannelDuplexHandler {
    public typealias InboundIn = NIOSSHAgentResponse
    public typealias InboundOut = NIOSSHAgentResponse
    public typealias OutboundIn = NIOSSHAgentTransaction
    public typealias OutboundOut = NIOSSHAgentRequest

    /// An internal Action struct to process side-effects of state transitions
    ///
    /// This avoids potential re-entrant state transitions related to inline processing
    /// of promise delivery
    private enum Action {
        case succeed(EventLoopPromise<NIOSSHAgentResponse>, NIOSSHAgentResponse)
        case fail(EventLoopPromise<NIOSSHAgentResponse>, Error)
        case nothing

        func doAction() {
            switch self {
            case .succeed(let promise, let response):
                promise.succeed(response)
            case .fail(let promise, let error):
                promise.fail(error)
            case .nothing:
                return
            }
        }
    }

    private enum State: ~Copyable {
        case idle
        case pending(NIOSSHAgentTransaction)

        mutating func nextTransaction(_ txn: NIOSSHAgentTransaction) -> Bool {
            switch consume self {
            case .idle:
                self = .pending(txn)
                return true
            case .pending(let currenttxn):
                self = .pending(currenttxn)
                return false
            }
        }

        mutating func succeed(_ response: NIOSSHAgentResponse) -> Action {
            switch consume self {
            case .idle:
                // This drops the response, but likely a logic error
                // can't seem to use precondition to check for an enum case
                fatalError("Inappropriate state for succeed call")
            case .pending(let currenttxn):
                self = .idle
                return .succeed(currenttxn.promise, response)
            }
        }

        mutating func fail(_ error: any Error) -> Action {
            switch consume self {
            case .idle:
                // This drops the response, but likely a logic error
                self = .idle
                return .nothing
            case .pending(let currenttxn):
                self = .idle
                return .fail(currenttxn.promise, error)
            }
        }
    }

    private var state = State.idle

    public init() {}

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let response = self.unwrapInboundIn(data)

        state.succeed(response).doAction()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        state.fail(NIOSSHAgentError.agentNotAvailable(reason: "Channel Inactive")).doAction()
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let transaction = unwrapOutboundIn(data)

        if state.nextTransaction(transaction) {
            _ = context.write(wrapOutboundOut(transaction.request))
        } else {
            transaction.promise.fail(NIOSSHAgentError.operationInProgress)
        }
    }
}

@available(*, unavailable)
extension NIOSSHAgentClientTransactionHandler: Sendable {}
