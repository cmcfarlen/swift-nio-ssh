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

// SSH Agent protocol as described here:
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-17
// and using the wire representation described here:
// https://datatracker.ietf.org/doc/html/rfc4251#section-5
//

import Foundation
import NIOCore

enum MessageNumber: UInt8, Sendable {
    case requestIdentities = 11
    case signRequest = 13
    case addIdentity = 17
    case removeIdentity = 18
    case removeAllIdentities = 19
    case addSmartcardKey = 20
    case removeSmartcardKey = 21
    case lock = 22
    case unlock = 23
    case addIdConstrained = 25
    case addSmartcardKeyContrained = 26
    case messageExtension = 27
    case failure = 5
    case success = 6
    case identitiesAnswer = 12
    case signResponse = 14
    case extensionFailure = 28
    case extensionResponse = 29
}

public enum SshAgentRequest: Sendable {
    case requestIdentities
    case signRequest(keyBlob: [UInt8], data: [UInt8], flags: UInt32)
    case addIdentity(Identity)

    var messageNumber: MessageNumber {
        switch self {
        case .requestIdentities:
            .requestIdentities
        case .signRequest:
            .signRequest
        case .addIdentity:
            .addIdentity
        }
    }

    package func encode(into buf: inout ByteBuffer) {
        buf.writeInteger(messageNumber.rawValue)

        switch self {
        case .signRequest(keyBlob: let blob, let data, let flags):
            buf.writeInteger(UInt32(blob.count))
            buf.writeBytes(blob)
            buf.writeInteger(UInt32(data.count))
            buf.writeBytes(data)
            buf.writeInteger(flags)
        case .addIdentity(let id):
            for var bb in id.identity {
                buf.writeSSHString(&bb)
            }
        default:
            break
        }
    }
}

public struct SshIdentity: Hashable, Sendable {
    let key: ByteBuffer
    let comment: String
}

extension SshIdentity: CustomStringConvertible {
    public var description: String {
        var bb = ByteBuffer(buffer: key)
        guard
            let id = bb.readSSHStringAsString(),
            let bytes = bb.readSSHString()
        else {
            return "unknown \(key) \(comment)"
        }

        return "\(id) \(Data(bytes.readableBytesView).base64EncodedString()) \(comment)"
    }
}

private func readIdentityList(_ buf: inout ByteBuffer) -> [SshIdentity] {
    guard let nKeys: UInt32 = buf.readInteger() else {
        return []
    }
    var result: [SshIdentity] = []
    result.reserveCapacity(Int(nKeys))

    for _ in 0..<nKeys {
        guard
            let key = buf.readSSHString(),
            let comment = buf.readSSHStringAsString()
        else {
            return result
        }
        result.append(SshIdentity(key: key, comment: comment))
    }

    if buf.readableBytes > 0 {
        print("Bytes left after reading list \(buf)")
    }

    return result
}

public enum SshAgentResponse: Sendable, Hashable {
    case generalSuccess
    case generalFailure
    case identities([SshIdentity])
    case signResponse(ByteBuffer)
    case notYetSupported(message: UInt8)

    init?(from buf: inout ByteBuffer) {
        guard let messageNumber: UInt8 = buf.readInteger(),
            let number = MessageNumber(rawValue: messageNumber)
        else {
            return nil
        }
        switch number {
        case .identitiesAnswer:
            self = .identities(readIdentityList(&buf))
        case .signResponse:
            if let sig = buf.readSSHString() {
                self = .signResponse(sig)
            } else {
                self = .generalFailure
            }
        case .failure:
            self = .generalFailure
        case .success:
            self = .generalSuccess
        default:
            self = .notYetSupported(message: number.rawValue)
        }
    }

}
