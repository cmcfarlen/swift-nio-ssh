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
import NIOFoundationCompat

/// SSH Identity used for adding identities to an ssh agent
///
/// This is essentially a private key, but I'm not certain
/// of the correlation between the SSH wire format and
/// the raw representation of keys in CryptoKit.
///
/// So for now, these are separately modeled but
/// if the arcane artifacts can be unearthed, perhaps
/// these itentities can be converted to useful SSH auth keys
///
/// Identities can be read from the ssh flavored PEM encoded file format.
/// The format is not well documented, but there is some information
/// [here](https://coolaj86.com/articles/the-openssh-private-key-format/)
/// as well as the source code.
///
/// Sendable because ByteBuffer is (unchecked) Sendable
public struct Identity: Sendable, Equatable {
    // Store the identity as an array of ByteBuffers
    // While the layout of identities varies by key type,
    // all of the fields are length prefixed, so they can
    // be treated opaquely
    let identity: [ByteBuffer]

    public init?(pemRepresentation: String) {
        let lines = pemRepresentation.split(separator: "\n")
        guard let first = lines.first,
            first == "-----BEGIN OPENSSH PRIVATE KEY-----",
            let last = lines.last,
            last == "-----END OPENSSH PRIVATE KEY-----",
            let base64body = Data(base64Encoded: lines.dropFirst().dropLast().joined())
        else {
            return nil
        }

        var pem = ByteBuffer(data: base64body)

        // Header magic and encryption info  Currenly don't support
        // decrypting
        guard let magic = pem.readNullTerminatedString(),
            magic == "openssh-key-v1",
            let key1 = pem.readSSHStringAsString(),
            key1 == "none",
            let key1 = pem.readSSHStringAsString(),
            key1 == "none",
            let zero: UInt32 = pem.readInteger(),
            zero == 0,
            let keyCount: UInt32 = pem.readInteger(),
            keyCount == 1
        else {
            return nil
        }

        guard
            // Next is the public key in ssh wire format, we don't need it
            let _ = pem.readSSHString(),

            // The private key section has the keytype, the public key again,
            // the private key parts (type dependent) and finally a comment
            let privateKeyInfo = pem.readSSHString()
        else {
            return nil
        }

        // The PEM buffer is padded at the end, but the read should fail at the padding.
        // Also, there are 8 bytes of something before the first key field, so skip that
        let startIdx = privateKeyInfo.readerIndex + 8
        var idx = startIdx
        var idParts: [ByteBuffer] = []
        while let bb = privateKeyInfo.getSSHString(at: idx) {
            idx += bb.readableBytes + 4
            idParts.append(bb)
        }

        self.identity = idParts
    }

    /// Return the key type as a string
    ///
    /// The key type name is always the first field in the PEM private key section
    var keyType: String? {
        identity.first.map { String(buffer: $0) }
    }

    /// Return the comment for the private key
    ///
    /// The comment field is the last field in the PEM private key section
    var comment: String? {
        identity.last.map { String(buffer: $0) }
    }
}
