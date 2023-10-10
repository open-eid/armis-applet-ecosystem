package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.Shareable;
import javacard.security.CryptoException;

public interface ECPrivateKeyService extends Shareable {

    // TLV constants
    public static final byte TAG_EC_CURVE_PRIME = (byte) 0x81;
    public static final byte TAG_EC_CURVE_COMPONENT_A = (byte) 0x82;
    public static final byte TAG_EC_CURVE_COMPONENT_B = (byte) 0x83;
    public static final byte TAG_EC_CURVE_GENERATOR = (byte) 0x84;
    public static final byte TAG_EC_CURVE_ORDER = (byte) 0x85;
    public static final byte TAG_EC_CURVE_PUBLIC_KEY = (byte) 0x86;
    public static final byte TAG_EC_CURVE_COFACTOR = (byte) 0x87;

    /**
     * Out-of-the-box decrypt-encrypt interface
     *
     * @param bAsn1PubKeyAndSignature ASN.1 formatted issuer ephemeral public key and its signature
     * @param bOffset ASN.1 structure offset in the buffer
     * @param bLength ASN.1 structure length in the buffer
     * @return an instance of {@link ECDHE} enabling to perform ECDHE-ECDSA operations
     */
    ECDHE performEcdhe(byte[] bAsn1PubKeyAndSignature, short bOffset, short bLength);

    /**
     * Out-of-the-box decrypt-encrypt interface
     *
     * @param signatureCipherAlgorithm
     * @return
     */
    ShareableSignature forSigning(byte signatureCipherAlgorithm);

    /**
     * Retrieve certificate.
     * If {@code bTargetArray} is present, this method copies at most {@code bTargetLength} bytes from the certificate
     * starting from {@code bSourceOffset} into the {@code bTargetArray} starting from {@code bTargetOffset} and returns
     * the actual number of bytes copied.
     * If {@code bTargetArray} is {@code null}, this method returns the length of the certificate minus
     * {@code bSourceOffset}.
     *
     * @param bSourceOffset offset into the certificate file
     * @param bTargetArray destination buffer where to write the bytes of the certificate into, or {@code null} if only
     *                     the length of the certificate file is needed
     * @param bTargetOffset offset into the {@code bTargetArray} where to start writing the certificate bytes from
     * @param bTargetLength maximum number of bytes to write into {@code bTargetArray}
     *
     * @return the number of bytes written into the {@code bTargetArray}, or total length of the certificate file minus
     *         {@code bSourceOffset} in case the {@code bTargetArray} is {@code null}
     */
    short getCertificate(short bSourceOffset, byte[] bTargetArray, short bTargetOffset, short bTargetLength);

    short getECCurveParameter(byte tag, byte[] bParameterTarget, short bOffset) throws CryptoException;

}
