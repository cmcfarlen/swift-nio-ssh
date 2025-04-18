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
import NIOCore
import NIOEmbedded
import System
import XCTest

@testable import NIOSSH

final class SshAgentTests: XCTestCase {
    static var agentProcess: Process? = nil

    override class func setUp() {
        print("SshAgent Setup\n")

        let p = Process()
        p.executableURL = URL(filePath: "/usr/bin/ssh-agent")
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

        print("Running ssh agent pid: \(p.processIdentifier)\n")
    }

    override class func tearDown() {
        print("SshAgent Teardown")
        if let agentProcess {
            agentProcess.terminate()
            agentProcess.waitUntilExit()
            print("SshAgent Exited")
        }
    }

    class func agentPath() -> String {
        let pid = ProcessInfo.processInfo.processIdentifier

        return "/tmp/niossh-agent-test.\(pid)"
    }

    func testConnectingToSshAgent() {
        if let p = SshAgentTests.agentProcess {
            XCTAssertGreaterThan(p.processIdentifier, 0)
        }
    }

    func testSshAgentHandler() throws {
        let channel = EmbeddedChannel()
        let handler = NIOSSHAgentClientHandler()

        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))
        XCTAssertNil(try channel.readOutbound())

        _ = try channel.connect(to: .init(unixDomainSocketPath: "/foo"))

        let request: SshAgentRequest = .requestIdentities

        _ = channel.write(request)

        // Verify the output wire format
        let bb = try channel.readOutbound(as: ByteBuffer.self)

        XCTAssertNotNil(bb)

        if var bb {
            XCTAssertEqual(bb.readableBytes, 1)

            let msgid: UInt8? = bb.readInteger()
            XCTAssertEqual(msgid, 11)
        }

        // simulate response
        var respbb = channel.allocator.buffer(capacity: 32)

        respbb.writeInteger(UInt8(5))

        XCTAssertEqual(respbb.readableBytes, 1)

        try channel.writeInbound(respbb)

        let response = try channel.readInbound(as: SshAgentResponse.self)

        XCTAssertEqual(response, .generalFailure)

        _ = try channel.finish()
    }

    func testEnd2End() throws {
        let group = MultiThreadedEventLoopGroup.singleton
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                // The pipeline processes data and events. Add your handler here.
                channel.pipeline.addHandlers([
                    MessageToByteHandler(SshAgentFrameCoder()),
                    ByteToMessageHandler(SshAgentFrameCoder()),
                    NIOSSHAgentClientHandler(),
                    NIOSSHAgentClientTransactionHandler(),
                ])
            }

        let channel = try bootstrap.connect(unixDomainSocketPath: SshAgentTests.agentPath()).wait()

        let promise = channel.eventLoop.makePromise(of: SshAgentResponse.self)
        let future = promise.futureResult.map { response -> SshAgentResponse in
            print(response)
            return response
        }

        let transaction = SshAgentTransaction(request: .requestIdentities, promise: promise)

        channel.writeAndFlush(transaction, promise: nil)

        let response = try future.wait()

        XCTAssertEqual(response, SshAgentResponse.identities([]))
    }

}
