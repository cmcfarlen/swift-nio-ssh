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

@preconcurrency import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat

public final class SshAgentUserAuthenticationDelegate<Bootstrap: NIOClientTCPBootstrapProtocol> {
    let socketPath: String
    var channel: Channel? = nil
    var pendingSignatures: [ByteBuffer: EventLoopPromise<NIOSSHUserAuthenticationOutcome>] = [:]
    let bootstrapper: (any EventLoop) throws -> Bootstrap
    let username: String

    // TODO(cmcfarlen): Add config to specify a key to use by label
    public init(username: String, _ bootstrapper: @escaping (any EventLoop) throws -> Bootstrap) {
        // TODO(cmcfarlen): Don't be so fatal
        guard let path = Self.environmentAgent else {
            fatalError("Failed to find ssh-agent socket from environment")
        }
        self.socketPath = path
        self.bootstrapper = bootstrapper
        self.username = username
    }

    static var environmentAgent: String? {
        ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"]
    }

    enum AgentAuthError: Error {

    }
}

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
        do {
            let bootstrap = try bootstrapper(authInfo.eventLoop)
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

            print("Connecting to \(socketPath)")
            let username = self.username
            bootstrap.connect(unixDomainSocketPath: socketPath)
                .whenComplete { result in
                    switch result {
                    case .failure(let err):
                        nextChallengePromise.fail(err)
                    case .success(let channel):
                        SshAgentUserAuthenticationDelegate.makeRequest(channel: channel, request: .requestIdentities)
                            .whenComplete { result in
                                switch result {
                                case .failure(let err):
                                    nextChallengePromise.fail(err)
                                case .success(let resp):
                                    switch resp {
                                    case .identities(let ids):
                                        print("Got \(ids.count) ids")
                                        let pubkey = ids[0].publicKey
                                        let signBytes = authInfo.generateSignableAuthPayload(
                                            username: username,
                                            forKey: pubkey
                                        )
                                        _ = channel.eventLoop.submit {
                                            SshAgentUserAuthenticationDelegate.makeRequest(
                                                channel: channel,
                                                request: .signRequest(
                                                    keyBlob: Array(ids[0].key.readableBytesView),
                                                    data: Array(signBytes.readableBytesView),
                                                    flags: 0
                                                )
                                            )
                                            .whenComplete { result in
                                                switch result {
                                                case .failure(let err):
                                                    nextChallengePromise.fail(err)
                                                case .success(let resp):
                                                    switch resp {
                                                    case .signResponse(let signature):
                                                        nextChallengePromise.succeed(
                                                            .init(
                                                                username: username,
                                                                serviceName: "",
                                                                offer: .agentSigned(
                                                                    pubkey,
                                                                    try? pubkey.rawBytesToSignature(raw: signature)
                                                                )
                                                            )
                                                        )
                                                    default:
                                                        nextChallengePromise.fail(
                                                            NIOSSHAgentError.unexpectedResponse(
                                                                reason:
                                                                    "Unexpected response for request signature: \(result)"
                                                            )
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    default:
                                        nextChallengePromise.fail(
                                            NIOSSHAgentError.unexpectedResponse(
                                                reason: "Unexpected response for request ids: \(resp)"
                                            )
                                        )
                                    }
                                }

                            }
                    }
                }

        } catch {
            nextChallengePromise.fail(error)
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
    private static func makeRequest(channel: Channel, request: SshAgentRequest) -> EventLoopFuture<SshAgentResponse> {
        let promise = channel.eventLoop.makePromise(of: SshAgentResponse.self)
        let future = promise.futureResult

        let transaction = SshAgentTransaction(request: request, promise: promise)

        channel.writeAndFlush(transaction, promise: nil)

        return future
    }
}
