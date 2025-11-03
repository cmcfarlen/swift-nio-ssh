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

/// An error thrown by SSH Agent operations.
///
/// For extensibility purposes, ``NIOSSHAgentError``s are composed of two parts. The first part is an
/// error type. This is like an enum, but extensible, and identifies the kind of error programmatically.
/// The second part is some opaque diagnostic data. This is not visible to your code, but is used to
/// help provide extra information for diagnostic purposes when logging this error.
///
/// Note that due to this construction ``NIOSSHAgentError`` is not equatable: only the ``NIOSSHAgentError/type`` is. This is deliberate,
/// as it is possible two errors have the same type but a different underlying cause or diagnostic data. For
/// this reason, if you need to compare two ``NIOSSHAgentError`` values you should explicitly compare their ``NIOSSHAgentError/type``.
public struct NIOSSHAgentError: Error {
    /// The type of this error, used to identify the kind of error that has been thrown.
    public struct ErrorType {
        private enum Base {
            case agentNotAvailable
            case operationInProgress
            case trailingBytes
            case badResponse
            case partialResponse
        }
        private var base: Base

        private init(_ base: Base) {
            self.base = base
        }

        public static let agentNotAvailable: ErrorType = .init(.agentNotAvailable)
        public static let operationInProgress: ErrorType = .init(.operationInProgress)
        public static let trailingBytes: ErrorType = .init(.trailingBytes)
        public static let badResponse: ErrorType = .init(.badResponse)
        public static let partialResponse: ErrorType = .init(.partialResponse)
    }

    /// The type of this error, used to identify the kind of error that has been thrown.
    public var type: ErrorType

    private var diagnostics: String?

    internal static func agentNotAvailable(reason: String) -> NIOSSHAgentError {
        NIOSSHAgentError(type: .agentNotAvailable, diagnostics: reason)
    }
    internal static let operationInProgress = NIOSSHAgentError(
        type: .operationInProgress,
        diagnostics: nil
    )
    internal static let trailingBytes = NIOSSHAgentError(
        type: .trailingBytes,
        diagnostics: "Unexpected trailing bytes remaining after read"
    )
    internal static let badResponse = NIOSSHAgentError(
        type: .badResponse,
        diagnostics: "Received bad response from agent"
    )
    internal static func partialResponse(expected: Int, received: Int) -> NIOSSHAgentError {
        NIOSSHAgentError(
            type: .partialResponse,
            diagnostics: "Expected \(expected) identities but could only parse \(received)"
        )
    }
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

/// A transaction representing a single SSH Agent request/response pair.
///
/// This structure encapsulates an SSH Agent request along with the promise that will be fulfilled
/// when the corresponding response is received. Transactions are used by ``NIOSSHAgentClientTransactionHandler``
/// to manage the request/response flow.
public struct NIOSSHAgentTransaction: Sendable {
    /// The SSH Agent request to send.
    public var request: NIOSSHAgentRequest

    /// The promise to complete when a response is received.
    public var promise: EventLoopPromise<NIOSSHAgentResponse>

    /// Create a new SSH Agent transaction.
    ///
    /// - Parameters:
    ///   - request: The SSH Agent request to send.
    ///   - promise: The promise to complete when a response is received.
    public init(request: NIOSSHAgentRequest, promise: EventLoopPromise<NIOSSHAgentResponse>) {
        self.request = request
        self.promise = promise
    }
}

/// A `ChannelDuplexHandler` that manages SSH Agent request/response transactions.
///
/// This handler ensures that only one SSH Agent transaction is in flight at any given time.
/// It pairs outbound requests with inbound responses, completing the associated promise when
/// a response is received. If a request is written while another is pending, the new request
/// will be rejected with ``NIOSSHAgentError/ErrorType/operationInProgress``.
///
/// This handler should be placed in the channel pipeline after ``NIOSSHAgentClientHandler``,
/// which handles the protocol encoding/decoding.
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
