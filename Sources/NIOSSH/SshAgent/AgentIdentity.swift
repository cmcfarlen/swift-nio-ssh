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
import NIOFoundationCompat

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A private key identity that can be added to an SSH Agent.
///
/// This type represents a private key in the format used by the SSH Agent protocol
/// for adding identities. It is distinct from ``NIOSSHIdentity``, which represents
/// a public key identifier returned by the agent.
///
/// ## Creating Identities
///
/// Identities can be created from OpenSSH PEM-encoded private key files:
///
/// ```swift
/// let pemData = try String(contentsOf: URL(fileURLWithPath: "~/.ssh/id_ed25519"))
/// guard let identity = NIOSSHAgentIdentity(pemRepresentation: pemData) else {
///     // Handle invalid or encrypted key
/// }
/// ```
///
/// ## Limitations
///
/// - Currently only supports unencrypted keys (cipher: "none", kdf: "none")
/// - Only supports single-key files (keyCount: 1)
/// - The internal representation is opaque and key-type dependent
///
/// ## PEM Format
///
/// The OpenSSH private key format is not well documented. For more information, see:
/// - [OpenSSH Private Key Format](https://coolaj86.com/articles/the-openssh-private-key-format/)
/// - OpenSSH source code
public struct NIOSSHAgentIdentity: Sendable, Equatable {
    // Store the identity as an array of ByteBuffers
    // While the layout of identities varies by key type,
    // all of the fields are length prefixed, so they can
    // be treated opaquely
    var identity: [ByteBuffer]

    /// Create an SSH Agent identity from an OpenSSH PEM-encoded private key.
    ///
    /// This initializer parses the OpenSSH private key format and extracts the key material
    /// needed to add the identity to an SSH Agent.
    ///
    /// - Parameter pemRepresentation: The PEM-encoded private key string, including the
    ///   "-----BEGIN OPENSSH PRIVATE KEY-----" and "-----END OPENSSH PRIVATE KEY-----" markers.
    ///
    /// - Returns: A new identity if the PEM data is valid and unencrypted, or `nil` if:
    ///   - The PEM format is invalid
    ///   - The key is encrypted (cipher != "none")
    ///   - The file contains multiple keys
    ///   - The key data cannot be parsed
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
            let key2 = pem.readSSHStringAsString(),
            key2 == "none",
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

    /// Returns the key type as a string.
    ///
    /// The key type name (e.g., "ssh-ed25519", "ecdsa-sha2-nistp256") is always the first
    /// field in the PEM private key section.
    ///
    /// - Returns: The key type string, or `nil` if the identity is malformed.
    public var keyType: String? {
        identity.first.map { String(buffer: $0) }
    }

    /// Returns the comment associated with this private key.
    ///
    /// The comment field is typically used to identify the key's origin or purpose
    /// (e.g., "user@hostname"). It is the last field in the PEM private key section.
    ///
    /// - Returns: The comment string, or `nil` if the identity is malformed.
    public var comment: String? {
        identity.last.map { String(buffer: $0) }
    }
}
