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

//
// This example program demonstrates connecting to an SSH Agent and performing
// some operations.  It starts a new ssh-agent instance so it doesn't interfere
// with any existing running agents.  A real ssh agent client might look at the
// environment variable SSH_AUTH_SOCK to check for a running agent and the
// socket to connect to.
//
// This example:
//   - Starts an ssh-agent listening on a temporary socket file
//   - Connects to the new agent
//   - Adds an ssh identity to the agent
//   - Uses that identity to request a signature
//   - stops the ssh agent

import Foundation
import NIO
import NIOSSH

let privateKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
    1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSnrELVzY4VC/3pS1n0s77GxeZJN+cR
    W+5rfKGkhTjPfcDVeRGSmyaHsC5aBQ8T8RkAPoKAL9HxPN9alD+Yix7AAAAAsPpEO4n6RD
    uJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKesQtXNjhUL/elL
    WfSzvsbF5kk35xFb7mt8oaSFOM99wNV5EZKbJoewLloFDxPxGQA+goAv0fE831qUP5iLHs
    AAAAAhAOIV/ZCxhuh9NVEcfKQ9QJsRkwxIQyhjAzjUTjNqD2FDAAAAEHRlc3RAa2V5ZWNk
    c2EyNTYBAgMEBQYH
    -----END OPENSSH PRIVATE KEY-----
    """
let publicKey =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKesQtXNjhUL/elLWfSzvsbF5kk35xFb7mt8oaSFOM99wNV5EZKbJoewLloFDxPxGQA+goAv0fE831qUP5iLHsA= test@keyecdsa256"

public class SshAgentProcess {
    var agentProcess: Process? = nil

    deinit {
        stop()
    }

    func start() {
        let p = Process()
        p.executableURL = URL(string: "file:///usr/bin/ssh-agent")
        p.arguments = ["-a", agentPath(), "-d"]
        let outputPipe = Pipe()
        let errorPipe = Pipe()

        p.standardOutput = outputPipe
        p.standardError = errorPipe

        do {
            try p.run()

            agentProcess = p
        } catch {
            fatalError("Running ssh agent failed")
        }
    }

    func stop() {
        if let agentProcess {
            print("Stopping ssh agent")
            agentProcess.terminate()
            agentProcess.waitUntilExit()
        }
        agentProcess = nil
    }

    func agentPath() -> String {
        let pid = ProcessInfo.processInfo.processIdentifier

        return "/tmp/niossh-agent-test.\(pid)"
    }

    func waitForAgent() -> String? {
        let path = agentPath()
        let start = Date()

        repeat {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date().timeIntervalSince(start) < 1

        return nil
    }

}

let agent = SshAgentProcess()

print("Starting an ssh agent")
agent.start()
print("Waiting for agent to start")
guard let agentPath = agent.waitForAgent() else {
    print("Failed to start agent")
    exit(1)
}

let group = MultiThreadedEventLoopGroup.singleton
let bootstrap = ClientBootstrap(group: group)
    .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
    .channelInitializer { channel in
        try! channel.pipeline.syncOperations.addHandlers([
            MessageToByteHandler(SshAgentFrameCoder()),
            ByteToMessageHandler(SshAgentFrameCoder()),
            NIOSSHAgentClientHandler(),
            NIOSSHAgentClientTransactionHandler(),
        ])
        return channel.eventLoop.makeSucceededVoidFuture()
    }

print("Connecting to \(agent.agentPath())")
let channel = try bootstrap.connect(unixDomainSocketPath: agent.agentPath()).wait()

func makeSyncRequest(_ request: SshAgentRequest) throws -> SshAgentResponse {
    let promise = channel.eventLoop.makePromise(of: SshAgentResponse.self)
    let future = promise.futureResult

    let transaction = SshAgentTransaction(request: request, promise: promise)

    channel.writeAndFlush(transaction, promise: nil)

    return try future.wait()
}

func extractIdentities(_ response: SshAgentResponse) -> [SshIdentity]? {
    switch response {
    case .identities(let ids):
        return ids
    default:
        return nil
    }
}

print("Identities before add: \(try makeSyncRequest(.requestIdentities))")

let identity = Identity(pemRepresentation: privateKey)!
print("Response from adding identity \(try makeSyncRequest(.addIdentity(identity)))")

let requestIdentitiesResponse = try makeSyncRequest(.requestIdentities)
print("Identities after add: \(requestIdentitiesResponse)")

if let ids = extractIdentities(requestIdentitiesResponse),
    let id = ids.first
{
    // an SSH client would sign a UserAuthSignablePayload, but the agent will sign anything for us
    let dataToSign = "Please sign this"
    let signResponse = try makeSyncRequest(.signRequest(keyBlob: id.keyBlob, data: [UInt8](dataToSign.utf8), flags: 0))
    print("Signature response: \(signResponse)")
} else {
    print("No signatures available with which to sign")
}

agent.stop()
