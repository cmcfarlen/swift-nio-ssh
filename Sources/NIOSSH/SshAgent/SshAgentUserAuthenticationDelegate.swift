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
import NIOConcurrencyHelpers
import NIOCore

public final class SshAgentUserAuthenticationDelegate<Bootstrap: NIOClientTCPBootstrapProtocol> {

    enum AgentConnectState {
        case notConnected
        case connecting([EventLoopPromise<Channel>])
        case connected(Channel)
        case waitingIdentities(Channel, [EventLoopPromise<[SshIdentity]>])
        case readyToRock(Channel, [SshIdentity])
        case failed(any Error)
    }

    let agentState: NIOLockedValueBox<AgentConnectState>
    let socketPath: String
    let bootstrapper: @Sendable (any EventLoop) throws -> Bootstrap
    let username: String

    // TODO(cmcfarlen): Add config to specify a key to use by label
    public init(username: String, _ bootstrapper: @Sendable @escaping (any EventLoop) throws -> Bootstrap) {
        // TODO(cmcfarlen): Don't be so fatal
        guard let path = Self.environmentAgent else {
            fatalError("Failed to find ssh-agent socket from environment")
        }
        self.agentState = .init(.notConnected)
        self.socketPath = path
        self.bootstrapper = bootstrapper
        self.username = username
    }

    static var environmentAgent: String? {
        ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"]
    }
}

extension SshAgentUserAuthenticationDelegate: Sendable {}

extension NIOSSHPublicKey {
    func rawBytesToSignature(raw: ByteBuffer) throws -> NIOSSHSignature? {
        do {
            var r = raw
            let s = try r.readSSHSignature()
            return s
        } catch {
            print("Caught error converting signature \(error)")
            throw error
        }
    }
}

extension SshAgentUserAuthenticationDelegate: NIOSSHClientUserAuthenticationDelegate {
    public func nextAuthenticationType(
        authInfo: any NIOSSHClientUserAuthenticationInfo,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        let username = self.username
        listIdentities(eventLoop: authInfo.eventLoop)
            .flatMap { ids in
                self.signAuthRequest(authInfo: authInfo, username: username, identity: ids[0])
            }
            .flatMap { pubkey, signature in
                nextChallengePromise.succeed(
                    .init(
                        username: username,
                        serviceName: "",
                        offer: .agentSigned(
                            pubkey,
                            signature
                        )
                    )
                )
                return authInfo.eventLoop.makeSucceededVoidFuture()
            }
            .whenFailure { err in
                print("Failure \(err)")
                nextChallengePromise.fail(err)
            }
    }

    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        fatalError("This overload not supported")
    }
}

extension SshAgentUserAuthenticationDelegate {
    private func getAgentChannel(eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        let promise = eventLoop.makePromise(of: Channel.self)
        var doConnect = false
        agentState.withLockedValue { state in
            switch state {
            case .notConnected:
                doConnect = true
                state = .connecting([promise])
            case .connecting(var waiters):
                waiters.append(promise)
                state = .connecting(waiters)
            case .connected(let channel), .readyToRock(let channel, _), .waitingIdentities(let channel, _):
                promise.succeed(channel)
            case .failed(let err):
                promise.fail(err)
            }
        }

        if doConnect {
            startAgentConnect(eventLoop: eventLoop)
        }

        return promise.futureResult
    }

    private func listIdentities(eventLoop: EventLoop) -> EventLoopFuture<[SshIdentity]> {
        let promise = eventLoop.makePromise(of: [SshIdentity].self)
        var doList = false
        agentState.withLockedValue { state in
            switch state {
            case .connected(let ch):
                state = .waitingIdentities(ch, [promise])
                doList = true
            case .waitingIdentities(let ch, var waiters):
                waiters.append(promise)
                state = .waitingIdentities(ch, waiters)
            case .readyToRock(_, let ids):
                promise.succeed(ids)
            case .failed(let err):
                promise.fail(err)
            default:
                doList = true
            }
        }

        if doList {
            getAgentChannel(eventLoop: eventLoop)
                .whenSuccess { channel in
                    self.startListingIdentities(channel: channel)
                }
        }

        return promise.futureResult
    }

    private func signAuthRequest(
        authInfo: NIOSSHClientUserAuthenticationInfo,
        username: String,
        identity: SshIdentity
    ) -> EventLoopFuture<(NIOSSHPublicKey, NIOSSHSignature?)> {
        let pubkey = identity.publicKey
        return getAgentChannel(eventLoop: authInfo.eventLoop)
            .flatMap { channel in
                let signBytes = authInfo.generateSignableAuthPayload(
                    username: username,
                    forKey: pubkey
                )
                return Self.makeRequest(
                    channel: channel,
                    request: .signRequest(
                        keyBlob: Array(identity.key.readableBytesView),
                        data: Array(signBytes.readableBytesView),
                        flags: 0
                    )
                )
            }
            .flatMap { (resp: SshAgentResponse) in
                switch resp {
                case .signResponse(let signature):
                    authInfo.eventLoop.makeSucceededFuture((pubkey, try? pubkey.rawBytesToSignature(raw: signature)))
                default:
                    authInfo.eventLoop.makeFailedFuture(
                        NIOSSHAgentError.unexpectedResponse(
                            reason:
                                "Unexpected response for request signature: \(resp)"
                        )
                    )
                }
            }
    }

    private func startAgentConnect(eventLoop: EventLoop) {
        do {
            let bootstrap = try bootstrapper(eventLoop)
                .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .channelInitializer { channel in
                    // The pipeline processes data and events. Add your handler here.
                    try! channel.pipeline.syncOperations.addHandlers([
                        MessageToByteHandler(SshAgentFrameCoder()),
                        ByteToMessageHandler(SshAgentFrameCoder()),
                        NIOSSHAgentClientHandler(),
                        NIOSSHAgentClientTransactionHandler(),
                    ])
                    return channel.eventLoop.makeSucceededVoidFuture()
                }

            bootstrap.connect(unixDomainSocketPath: socketPath)
                .whenComplete { [weak self] result in
                    self?.agentState.withLockedValue { state in
                        switch state {
                        case .connecting(let waiters):
                            switch result {
                            case .success(let channel):
                                for w in waiters {
                                    w.succeed(channel)
                                }
                                state = .connected(channel)
                            case .failure(let err):
                                for w in waiters {
                                    w.fail(err)
                                }
                                state = .failed(err)
                            }
                        default:
                            fatalError("Unexpected SshAgent connect state.  Expected .connecting, got \(state)")
                        }
                    }
                }
        } catch {
            fatalError("Failed bootstrapping ssh agent connection \(error)")
        }
    }

    private func startListingIdentities(channel: Channel) {
        Self.makeRequest(channel: channel, request: .requestIdentities)
            .whenComplete { [weak self] result in
                self?.agentState.withLockedValue { state in
                    switch state {
                    case .waitingIdentities(let channel, let waiters):
                        switch result {
                        case .success(let resp):
                            switch resp {
                            case .identities(let ids):
                                for w in waiters {
                                    w.succeed(ids)
                                }
                                state = .readyToRock(channel, ids)
                            default:
                                let err =
                                    NIOSSHAgentError.unexpectedResponse(
                                        reason:
                                            "Unexpected response for list identities: \(resp)"
                                    )
                                for w in waiters {
                                    w.fail(err)
                                }
                                _ = channel.close()
                                state = .failed(err)
                            }
                        case .failure(let err):
                            for w in waiters {
                                w.fail(err)
                            }
                            _ = channel.close()
                            state = .failed(err)
                        }
                    default:
                        fatalError("Unexpected SshAgent connect state.  Expected .waitingIdentities, got \(state)")
                    }

                }
            }
    }

}

extension SshAgentUserAuthenticationDelegate {
    private static func makeRequest(channel: Channel, request: SshAgentRequest) -> EventLoopFuture<SshAgentResponse> {
        let promise = channel.eventLoop.makePromise(of: SshAgentResponse.self)
        let future = promise.futureResult

        let transaction = SshAgentTransaction(request: request, promise: promise)

        _ = channel.eventLoop.submit {
            channel.writeAndFlush(transaction, promise: nil)
        }

        return future
    }
}
