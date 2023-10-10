package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.Shareable;

public interface ECDHE extends Shareable {

    /**
     *
     * @param cipherAlgorithm
     * @param paddingAlgorithm
     * @param secretMode
     * @param publicData
     * @param publicOffset
     * @param publicLength
     * @return
     */
    ShareableCipher forAesCrypto(
            byte cipherAlgorithm, byte paddingAlgorithm, byte secretMode,
            byte[] publicData, short publicOffset, short publicLength
    );

    /**
     * Retrieve the resultant shared secret of the ECDHE-ECDSA operation.
     *
     * @param bTargetArray destination buffer where to write the bytes of the shared secret into
     * @param bTargetOffset offset into the {@code bTargetArray} where to start writing the shared secret bytes from
     * @return the number of bytes written into the {@code bTargetArray}
     */
    short getSecret(byte[] bTargetArray, short bTargetOffset);

    /**
     * Retrieve the applet ephemeral keypair's public key that is signed by manager applet maintained private key.
     * The ephemeral public key's elliptic curve point and the ECDSA-SHA384 signature will be formatted as an ASN.1 encoded structure.
     *
     * @param bTargetArray destination buffer where to write the bytes of the public key and signature into
     * @param bTargetOffset offset into the {@code bTargetArray} where to start writing the public key and signature bytes from
     * @return the number of bytes written into the {@code bTargetArray}
     */
    short getSignedEphemeralPublicKey(byte[] bTargetArray, short bTargetOffset);

    /**
     * Request the system resources used by this object to be released.
     * NB: After invoking {@link ECDHE#dispose()}, this object becomes invalid!
     */
    void dispose();

}
