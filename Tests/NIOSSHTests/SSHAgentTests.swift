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
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSnrELVzY4VC/3pS1n0s77GxeZJN+cR
        W+5rfKGkhTjPfcDVeRGSmyaHsC5aBQ8T8RkAPoKAL9HxPN9alD+Yix7AAAAAsPpEO4n6RD
        uJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKesQtXNjhUL/elL
        WfSzvsbF5kk35xFb7mt8oaSFOM99wNV5EZKbJoewLloFDxPxGQA+goAv0fE831qUP5iLHs
        AAAAAhAOIV/ZCxhuh9NVEcfKQ9QJsRkwxIQyhjAzjUTjNqD2FDAAAAEHRlc3RAa2V5ZWNk
        c2EyNTYBAgMEBQYH
        -----END OPENSSH PRIVATE KEY-----
        """
    static let publicKey =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKesQtXNjhUL/elLWfSzvsbF5kk35xFb7mt8oaSFOM99wNV5EZKbJoewLloFDxPxGQA+goAv0fE831qUP5iLHsA= test@keyecdsa256"
}

final class SshAgentTests: XCTestCase {

    func testIdentity() throws {
        let identity = Identity(pemRepresentation: AgentTestFixtures.privateKey)

        XCTAssertNotNil(identity)
        XCTAssertEqual(identity?.keyType, "ecdsa-sha2-nistp256")
        XCTAssertEqual(identity?.comment, "test@keyecdsa256")
    }

    func testSshAgentHandler() throws {
        let channel = EmbeddedChannel()
        let handler = NIOSSHAgentClientHandler()

        func testTransaction(
            request: SshAgentRequest,
            testEncode: (inout ByteBuffer) -> Void,
            buildResponse: ((inout ByteBuffer) -> Void)? = nil,
            testResponse: ((SshAgentResponse?) -> Void)? = nil
        ) throws {
            _ = channel.write(request)

            let bb = try channel.readOutbound(as: ByteBuffer.self)
            XCTAssertNotNil(bb)

            guard var bb else {
                return
            }

            testEncode(&bb)
            bb.clear()
            if let buildResponse {
                buildResponse(&bb)
                try channel.writeInbound(bb)

                let response = try channel.readInbound(as: SshAgentResponse.self)
                testResponse?(response)
            }
        }

        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))
        XCTAssertNil(try channel.readOutbound())

        _ = try channel.connect(to: .init(unixDomainSocketPath: "/foo"))

        try testTransaction(request: .requestIdentities) { bb in
            XCTAssertEqual(bb.readableBytes, 1)

            let msgid: UInt8? = bb.readInteger()
            XCTAssertEqual(msgid, 11)
        }

        try testTransaction(request: .requestIdentities) { bb in
            XCTAssertEqual(bb.readableBytes, 1)

            let msgid: UInt8? = bb.readInteger()
            XCTAssertEqual(msgid, 11)
        } buildResponse: { bb in
            bb.writeInteger(MessageNumber.identitiesAnswer.rawValue)
            bb.writeInteger(UInt32(1))
            bb.writeSSHString("publickey".utf8)
            bb.writeSSHString("comment".utf8)
        } testResponse: { response in
            XCTAssertNotNil(response)
            guard let response else {
                return
            }
            switch response {
            case .identities(let ids):
                XCTAssertEqual(ids.count, 1)
                XCTAssertEqual(ids[0].key.readableBytes, 9)
                XCTAssertEqual(ids[0].comment, "comment")
            default:
                return
            }
        }

        let identity = Identity(pemRepresentation: AgentTestFixtures.privateKey)!
        try testTransaction(request: .addIdentity(identity)) { bb in
            // The id request should just have the message number and a copy of identity
            XCTAssertEqual(bb.readInteger(as: UInt8.self), MessageNumber.addIdentity.rawValue)
            let idBytes = identity.identity.map(\.readableBytes).reduce(0, +) + (identity.identity.count * 4)
            XCTAssertEqual(bb.readableBytes, idBytes)
        }

        _ = try channel.finish()
    }
}
