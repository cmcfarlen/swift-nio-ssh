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

import CryptoKit
import Foundation
import NIO
import NIOCore
import NIOEmbedded
import NIOFoundationCompat
import System
import XCTest

@testable import NIOSSH

enum AgentTestFixtures {
    static let privateKey =
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRKMl6GDYWg1rVg1TFyWzAHweCc+EN+
        Ko70piPjiVd0XQhR0ysmYnTm+9b16ahe9aI73dBzZl+kG0mzWnZ+W8O7AAAAsBb8hvkW/I
        b5AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEoyXoYNhaDWtWDV
        MXJbMAfB4Jz4Q34qjvSmI+OJV3RdCFHTKyZidOb71vXpqF71ojvd0HNmX6QbSbNadn5bw7
        sAAAAgGn8s3ccM2VsVk0ljNv+rq7ueB//lwxdsOLd2wfb8I04AAAAUY21jZmFybGVuQHBl
        YnMubG9jYWwBAgME
        -----END OPENSSH PRIVATE KEY-----
        """
    static let publicKey =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEoyXoYNhaDWtWDVMXJbMAfB4Jz4Q34qjvSmI+OJV3RdCFHTKyZidOb71vXpqF71ojvd0HNmX6QbSbNadn5bw7s= cmcfarlen@pebs.local"
}

final class SshAgentTests: XCTestCase {

    func testIdentity() throws {
        let identity = Identity(pemRepresentation: AgentTestFixtures.privateKey)

        XCTAssertEqual(identity?.identity[0], ByteBuffer(string: "ecdsa-sha2-nistp256"))
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
}
