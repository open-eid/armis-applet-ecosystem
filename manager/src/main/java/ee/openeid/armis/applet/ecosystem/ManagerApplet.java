package ee.openeid.armis.applet.ecosystem;

import ee.openeid.armis.applet.ecosystem.libs.AppletRegistry;
import ee.openeid.armis.applet.ecosystem.libs.ECDHE;
import ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService;
import ee.openeid.armis.applet.ecosystem.libs.ShareableSignature;
import ee.openeid.armis.applet.ecosystem.libs.TlvUtils;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import org.globalplatform.Personalization;

import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SHORT_0;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SIZE_OF_SHORT;

public class ManagerApplet extends Applet implements AppletRegistry, ECPrivateKeyService, ExtendedLength, Personalization {

    // Clear-on-reset reusable transient buffer size
    // The size of this buffer should be as small as possible since the RAM allocated for CLEAR_ON_RESET buffers is not available to other applets
    private static final short SIZE_BUFFER_CLEAR_ON_RESET = (short) (SIZE_OF_SHORT << 1);

    // Certificate file size limits
    private static final short MIN_CERTIFICATE_FILE_SIZE = (short) 0x0001;
    private static final short MAX_CERTIFICATE_FILE_SIZE = (short) 0x0800;

    // APDU constants
    private static final byte INS_GET_DATA = (byte) 0xCB;
    private static final byte INS_PUT_DATA = (byte) 0xDB;
    private static final byte INS_KEY_PAIR_GENERATE = (byte) 0x47;
    private static final byte CLA_MANAGER_APPLET = (byte) 0xB0;

    private static final short LENGTH_EC_FP_320 = 320;
    private static final short LENGTH_EC_FP_512 = 512;


    // TLV constants
    private static final short TAG_CARDHOLDER_CERTIFICATE = (short) 0x7F21;
    private static final short TAG_PUBLIC_KEY_PARAMS = (short) 0x7F49;

    private static final byte TAG_UNIVERSAL_INTEGER = (byte) 0x02;
    private static final byte TAG_UNIVERSAL_OCTET_STRING = (byte) 0x04;
    private static final byte TAG_UNIVERSAL_SEQUENCE = (byte) 0x30;

    // Constants for applet lifecycle states
    private static final byte LIFECYCLE_UNINITIALIZED = (byte) 0;
    private static final byte LIFECYCLE_INSTALLED_BIT = (byte) 0x01;
    private static final byte LIFECYCLE_INSTALLED = LIFECYCLE_INSTALLED_BIT;
    private static final byte LIFECYCLE_KEYPAIR_GENERATED_BIT = (byte) 0x02;
    private static final byte LIFECYCLE_CERTIFICATE_STORED_BIT = (byte) 0x04;
    private static final byte LIFECYCLE_PERSONALIZED = (byte) (
            LIFECYCLE_INSTALLED_BIT | LIFECYCLE_KEYPAIR_GENERATED_BIT | LIFECYCLE_CERTIFICATE_STORED_BIT
    );

    // Indexes of `transientECKeys` objects
    private static final byte IDX_TRANSIENT_PRIVATE = 0;
    private static final byte IDX_TRANSIENT_PUBLIC = 1;
    private static final byte IDX_EPH_TRANSIENT_PRIVATE = 2;
    private static final byte IDX_EPH_TRANSIENT_PUBLIC = 3;


    // Instance state (in EEPROM)
    private byte lifeCycleState;
    private byte[] certificateFile;
    private ECPrivateKey ecPrivateKey;
    private ECPrivateKey ecEphPrivateKey;
    private ECPublicKey ecEphPublicKey;

    // Clear-on-reset (RAM)
    private Object[] transientECKeys;
    private byte[] clearOnResetTransientMemory; // Reusable buffer

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Require object deletion support on this device
        if (!JCSystem.isObjectDeletionSupported()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Create an instance of the ManagerApplet
        ManagerApplet instance = new ManagerApplet();

        byte instanceAidLength = bArray[bOffset];
        // Check if explicit instance AID is present in the payload
        if (instanceAidLength > 0) {
            // Register the applet using the specified instance AID
            instance.register(bArray, (short) (bOffset + 1), instanceAidLength);
        } else {
            // Register the applet using default AID
            instance.register();
        }

        // Mark the applet as installed
        instance.lifeCycleState = LIFECYCLE_INSTALLED;
    }

    @Override
    public ECDHE performEcdhe(byte[] bAsn1PubKeyAndSignature, short bOffset, short bLength) {
        if (lifeCycleState != LIFECYCLE_PERSONALIZED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Create local handles for keys
        ECPrivateKey appletPrivateKey = ecPrivateKey;
        ECPrivateKey ephPrivateKey = ecEphPrivateKey;
        ECPublicKey ephPublicKey = ecEphPublicKey;

        // Calculate key size in bytes: (key-size-in-bits + 7) / 8
        short keySize = (short) ((short) (appletPrivateKey.getSize() + 7) >> 3);
        // Calculate EC point size in bytes: 1 + 2 * key-size-in-bytes = 1 header byte + 2 co-ordinates
        short pointSize = (short) (1 + (keySize << 1));
        // Calculate EC plain signature size in bytes: 2 * key-size-in-bytes = 2 co-ordinates
        // short signatureSize = (short) (keySize << 1);

        // Use transient memory for parser metadata buffer
        byte[] parserMetadata = clearOnResetTransientMemory;
        // Initialize the parser metadata buffer with the input data offset and length values
        TlvUtils.setParserMetadata(bOffset, bLength, parserMetadata, SHORT_0);
        // Ensure the first TLV tag is SEQUENCE and obtain its length
        bLength = TlvUtils.ensureTlvTag1AndParseLength(TAG_UNIVERSAL_SEQUENCE, bAsn1PubKeyAndSignature, parserMetadata, SHORT_0);
        // Ensure the obtained TLV length is equal to the remaining length of the parsable data
        if (bLength != TlvUtils.getParseLength(parserMetadata, SHORT_0)) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        // Ensure the next TLV tag is OCTET STRING and obtain its length
        bLength = TlvUtils.ensureTlvTag1AndParseLength(TAG_UNIVERSAL_OCTET_STRING, bAsn1PubKeyAndSignature, parserMetadata, SHORT_0);
        // Ensure the obtained TLV length is equal to public key EC point size
        if (bLength != pointSize) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        // Ensure enough input data is available to fit public key EC point
        bOffset = TlvUtils.ensureParsableInputAvailable(pointSize, parserMetadata, SHORT_0);

        try {
            // Generate temporary ephemeral key-pair
            new KeyPair(ephPublicKey, ephPrivateKey).genKeyPair();
            // Create an instance of key-agreement with the specified algorithm
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, true);
            // Initialize the key-agreement with the newly generated ephemeral private key
            keyAgreement.init(ephPrivateKey);

            // Create buffer for shared secret
            byte[] sharedSecret = new byte[keySize]; // TODO: Why not to use `clearOnResetTransientMemory`?
            // Generate the shared secret based on the generated ephemeral private key and issuer ephemeral public key, and verify its length
            if (keyAgreement.generateSecret(bAsn1PubKeyAndSignature, bOffset, pointSize, sharedSecret, SHORT_0) != keySize) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // Calculate the TLV length of public key tag(OCTET STRING) + length + value
            short pubTlvLength = TlvUtils.bytesRequiredForTlv1(pointSize);
            // Calculate the TLV length of plain signature tag(OCTET STRING) + length + (r || s)
            short sigTlvLength = TlvUtils.bytesRequiredForTlv1(
                    (short) (TlvUtils.bytesRequiredForTlv1((short) (keySize + 1)) << 1)
            );
            // Calculate the expected total maximum length of the TLV structure
            bLength = TlvUtils.bytesRequiredForTlv1((short) (pubTlvLength + sigTlvLength));
            // Create buffer for signed ephemeral public key
            byte[] signedEphemeralPublicKey = new byte[bLength]; // TODO: Why not to use `clearOnResetTransientMemory`?

            // Calculate the maximum offset of the public key data and skip the outer SEQUENCE
            short pubTlvOffset = TlvUtils.bytesRequiredForTlvTag1AndLength(bLength);
            // Write the tag (OCTET STRING) and length of the public key into the buffer, starting from the previously calculated offset
            short pubOffset = TlvUtils.writeTlvTag1AndLength(TAG_UNIVERSAL_OCTET_STRING, pointSize, signedEphemeralPublicKey, pubTlvOffset);
            // Write the public key EC point into the buffer and verify the written length
            if (ephPublicKey.getW(signedEphemeralPublicKey, pubOffset) != pointSize) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            short sigTlvOffset = (short) (pubOffset + pointSize);

            Signature signature = null;
            try {
                // Create an instance of signature with the specified algorithm.
                // NB! Sadly JavaCard 3.0.4 has only `SIG_CIPHER_ECDSA`. `SIG_CIPHER_ECDSA_PLAIN` was introduced in `3.0.5`.
                signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, true);
                // Initialize the signature with the private key of the applet
                signature.init(appletPrivateKey, Signature.MODE_SIGN);
                // Sign the public key, write the signature into the buffer right after the public key, and acquire the actual length of the signature
                sigTlvLength = signature.sign(signedEphemeralPublicKey, pubOffset, pointSize, signedEphemeralPublicKey, sigTlvOffset);
            } finally {
                signature = null;
            }
            // Calculate the sum of the public key and signature lengths
            bLength = (short) (pubTlvLength + sigTlvLength);
            // Calculate the actual offset of the TLV structure (taking into account the actual length of the signature)
            bOffset = (short) (pubTlvOffset - TlvUtils.bytesRequiredForTlvTag1AndLength(bLength));
            // Write the SEQUENCE tag and its actual length in front of the public key, increment the total length by the returned offset
            bLength += TlvUtils.writeTlvTag1AndLength(TAG_UNIVERSAL_SEQUENCE, bLength, signedEphemeralPublicKey, bOffset);
            // Adjust the total length by taking the offset of the TLV structure into account
            bLength -= bOffset;

            // Build and return the ECDHE object
            return new SharedECDHE(sharedSecret, signedEphemeralPublicKey, bOffset, bLength);
        } finally {
            // Schedule GC for dangling objects
            JCSystem.requestObjectDeletion();
        }
    }

    @Override
    public ShareableSignature forSigning(byte signatureCipherAlgorithm) {
        if (lifeCycleState != LIFECYCLE_PERSONALIZED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        try {
            Signature signature = Signature.getInstance(signatureCipherAlgorithm, true);
            signature.init(ecPrivateKey, Signature.MODE_SIGN);
            return new SharedSignature(signature);
        } finally {
            // Schedule GC for dangling objects
            JCSystem.requestObjectDeletion();
        }
    }

    @Override
    public short getCertificate(short bSourceOffset, byte[] bTargetArray, short bTargetOffset, short bTargetLength) {
        if (lifeCycleState != LIFECYCLE_PERSONALIZED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] bSourceArray = certificateFile;
        short length = (short) bSourceArray.length;
        // Ensure offset into the certificate file is valid
        if (bSourceOffset < (short) 0 || bSourceOffset > length) {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }

        // Get the number of available certificate bytes
        length -= bSourceOffset;

        // Return the length if no target buffer provided
        if (bTargetArray == null) {
            return length;
        }

        // Find the actual number of bytes to copy
        if (bTargetLength < length) {
            length = bTargetLength;
        }
        // Copy the bytes into the target buffer
        Util.arrayCopyNonAtomic(bSourceArray, bSourceOffset, bTargetArray, bTargetOffset, length);
        // Return the number of bytes copied
        return length;
    }

    @Override
    public short getECCurveParameter(byte tag, byte[] bParameterTarget, short bOffset) throws CryptoException {
        switch (tag) {
            case TAG_EC_CURVE_PRIME: return ecEphPublicKey.getField(bParameterTarget, bOffset);
            case TAG_EC_CURVE_COMPONENT_A: return ecEphPublicKey.getA(bParameterTarget, bOffset);
            case TAG_EC_CURVE_COMPONENT_B: return ecEphPublicKey.getB(bParameterTarget, bOffset);
            case TAG_EC_CURVE_GENERATOR: return ecEphPublicKey.getG(bParameterTarget, bOffset);
            case TAG_EC_CURVE_ORDER: return ecEphPublicKey.getR(bParameterTarget, bOffset);
            case TAG_EC_CURVE_COFACTOR: Util.setShort(bParameterTarget, bOffset, ecEphPublicKey.getK()); return SIZE_OF_SHORT;
            default: CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return SHORT_0; // For compiler
    }

    @Override
    public Shareable getShareableInterfaceObject(AID clientAid, byte parameter) {
        return this;
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA_MANAGER_APPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    @Override
    public short processData(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        // The most significant bit of P1 parameter declares if the command is the last one in the row
        //boolean isLast = (inBuffer[(byte) (inOffset + ISO7816.OFFSET_P1)] & 0x80) == 0x80;
        // The value of P2 declares the sequence number of the command
        //short sequence = Util.makeShort((byte) 0, inBuffer[(byte) (inOffset + ISO7816.OFFSET_P2)]);

        // Use transient memory for parser metadata buffer
        byte[] parserMetadata = clearOnResetTransientMemory;
        // Initialize the parser metadata buffer with the input data offset and length values
        TlvUtils.setParserMetadata(inOffset, inLength, parserMetadata, SHORT_0);
        // Ensure the input is long enough and skip to the beginning of the nested command
        TlvUtils.ensureParsableInputAvailable(ISO7816.OFFSET_CDATA, parserMetadata, SHORT_0);
        // Ensure the input is long enough and acquire the offset of nested INS byte
        inOffset = TlvUtils.ensureParsableInputAvailable(TlvUtils.SIZE_OF_BYTE, parserMetadata, SHORT_0);
        byte ins = inBuffer[inOffset];

        switch (ins) {
            case INS_GET_DATA:
            case INS_PUT_DATA:
                // Acquire the 2-byte data identifier tag from the position of nested P1-P2
                short tag = TlvUtils.parseTlvTag2(inBuffer, parserMetadata, SHORT_0);
                // TODO Currently this logic requires that both GET_DATA and PUT_DATA must have Lc > 0.
                //  Do we want to support a GET_DATA variant with Lc = 0?
                // Ensure the input is long enough and acquire the offset of the nested Lc byte
                inOffset = TlvUtils.ensureParsableInputAvailable(TlvUtils.SIZE_OF_BYTE, parserMetadata, SHORT_0);
                // Acquire the input length from the nested Lc byte and increment the current offset by one
                inLength = Util.makeShort(TlvUtils.BYTE_0, inBuffer[inOffset++]);

                if (ins == INS_GET_DATA) {
                    // Ensure the (obtained length + Le byte length) is not greater than what is actually available
                    if ((short) (inLength + 1) > TlvUtils.getParseLength(parserMetadata, SHORT_0)) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                    // Acquire the expected response length from the nested Le byte
                    short responseLength = Util.makeShort(TlvUtils.BYTE_0, inBuffer[(short) (inOffset + inLength)]);
                    if (responseLength == 0) { // Le value special handling: 256 is encoded as 0x00
                        responseLength = 256;
                    }
                    // Calculate how many bytes are available for writing in outBuffer
                    short outLength = (short) (outBuffer.length - outOffset);
                    // If we cannot write at least 1 byte to outBuffer, fail immediately
                    if (outLength < 1) {
                        ISOException.throwIt(ISO7816.SW_UNKNOWN);
                    }
                    // Adjust the response length if we must return fewer bytes than was expected
                    if (responseLength > outLength) {
                        responseLength = outLength;
                    }
                    switch (tag) {
                        case TAG_CARDHOLDER_CERTIFICATE:
                            return getAppletCertificate(inBuffer, inOffset, inLength, outBuffer, outOffset, responseLength);
                        default:
                            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    }
                    break;
                } else {
                    // Ensure the obtained length is not greater than what is actually available
                    if (inLength > TlvUtils.getParseLength(parserMetadata, SHORT_0)) {
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    }
                    switch (tag) {
                        case TAG_PUBLIC_KEY_PARAMS:
                            return putKeyPairProfile(inBuffer, inOffset, inLength);
                        case TAG_CARDHOLDER_CERTIFICATE:
                            return putAppletCertificate(inBuffer, inOffset, inLength);
                        default:
                            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    }
                    break;
                }
            case INS_KEY_PAIR_GENERATE:
                return generateAppletKeyPair(outBuffer, outOffset);
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
        }

        return 0; // Make compiler happy
    }

    private ManagerApplet() {
        transientECKeys = JCSystem.makeTransientObjectArray((short) 4, JCSystem.CLEAR_ON_RESET);
        lifeCycleState = LIFECYCLE_UNINITIALIZED;
        // Create reusable clear-on-reset transient buffer
        clearOnResetTransientMemory = JCSystem.makeTransientByteArray(SIZE_BUFFER_CLEAR_ON_RESET, JCSystem.CLEAR_ON_RESET);
    }

    private ECKey getTransientECKey(byte typeIndex) {
        return (ECKey) transientECKeys[typeIndex];
    }

    private ECKey getTransientECKeyOrThrow(byte typeIndex, short reason) {
        ECKey value = (ECKey) transientECKeys[typeIndex];
        if (value == null) ISOException.throwIt(reason);
        return value;
    }

    private ECKey setTransientECKey(byte typeIndex, ECKey value) {
        transientECKeys[typeIndex] = value;
        return value;
    }

    private short putKeyPairProfile(byte[] inBuffer, short inOffset, short inLength) {
        ECKey ecPrivateKey = getTransientECKey(IDX_TRANSIENT_PRIVATE);
        short keySize = ecPrivateKey != null
                ? ((Key) ecPrivateKey).getSize()
                : -1;
        short keySizeInBytes = (short) ((short) (keySize + 7) >> 3);

        // Use transient memory for parser metadata buffer
        byte[] parserMetadata = clearOnResetTransientMemory;
        // Initialize the parser metadata buffer with the input data offset and length values
        TlvUtils.setParserMetadata(inOffset, inLength, parserMetadata, SHORT_0);

        do {
            byte tag = TlvUtils.parseTlvTag1(inBuffer, parserMetadata, SHORT_0);
            short length = TlvUtils.parseTlvLength(inBuffer, parserMetadata, SHORT_0);
            inOffset = TlvUtils.ensureParsableInputAvailable(length, parserMetadata, SHORT_0);

            try {
                switch (tag) {
                    case TAG_EC_CURVE_PRIME: // Prime
                        keySize = getEcFpFieldLength(length);
                        setTransientECKey(IDX_TRANSIENT_PRIVATE, (ECKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, keySize, false));
                        setTransientECKey(IDX_TRANSIENT_PUBLIC, (ECKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, keySize, false));
                        setTransientECKey(IDX_EPH_TRANSIENT_PRIVATE, (ECKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, keySize, false));
                        setTransientECKey(IDX_EPH_TRANSIENT_PUBLIC, (ECKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, keySize, false));
                        keySizeInBytes = (short) ((short) (keySize + 7) >> 3);
                        for (byte i = 0; i < (byte) transientECKeys.length; i++) {
                            getTransientECKey(i).setFieldFP(inBuffer, inOffset, length);
                        }
                        break;
                    case TAG_EC_CURVE_COMPONENT_A: // Component A
                        if (length != keySizeInBytes) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        for (byte i = 0; i < (byte) transientECKeys.length; i++) {
                            getTransientECKeyOrThrow(i, ISO7816.SW_DATA_INVALID).setA(inBuffer, inOffset, length);
                        }
                        break;
                    case TAG_EC_CURVE_COMPONENT_B: // Component B
                        if (length != keySizeInBytes) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        for (byte i = 0; i < (byte) transientECKeys.length; i++) {
                            getTransientECKeyOrThrow(i, ISO7816.SW_DATA_INVALID).setB(inBuffer, inOffset, length);
                        }
                        break;
                    case TAG_EC_CURVE_GENERATOR: // Generator
                        // Ensure length equals to EC point size: 1 + 2 * key-size-in-bytes
                        if (length != (short) (1 + (keySizeInBytes << 1))) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        for (byte i = 0; i < (byte) transientECKeys.length; i++) {
                            getTransientECKeyOrThrow(i, ISO7816.SW_DATA_INVALID).setG(inBuffer, inOffset, length);
                        }
                        break;
                    case TAG_EC_CURVE_ORDER: // Order of the generator
                        if (length != keySizeInBytes) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        for (byte i = 0; i < (byte) transientECKeys.length; i++) {
                            getTransientECKeyOrThrow(i, ISO7816.SW_DATA_INVALID).setR(inBuffer, inOffset, length);
                        }
                        break;
                    case TAG_EC_CURVE_COFACTOR: // Cofactor
                        if (length < TlvUtils.SIZE_OF_BYTE || length > TlvUtils.SIZE_OF_SHORT) {
                            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        }
                        short cofactor = length == TlvUtils.SIZE_OF_SHORT
                                ? Util.getShort(inBuffer, inOffset)
                                : Util.makeShort(TlvUtils.BYTE_0, inBuffer[inOffset]);
                        for (byte i = 0; i < (byte) transientECKeys.length; i++) {
                            getTransientECKeyOrThrow(i, ISO7816.SW_DATA_INVALID).setK(cofactor);
                        }
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        break;
                }
            } catch (CryptoException e) {
                // KeyBuilder.buildKey(byte, short, boolean) - CryptoException.NO_SUCH_ALGORITHM: requested algorithm associated with the specified type, size of key and key encryption interface is not supported.
                // ECKey.setFieldFP(byte[], short, short), ECKey.setA(byte[], short, short), ECKey.setB(byte[], short, short), ECKey.setG(byte[], short, short), ECKey.setR(byte[], short, short)
                //  - CryptoException.ILLEGAL_VALUE - length parameter is 0 or invalid or if the input parameter data is inconsistent with the key length or if input data decryption is required and fails.
                switch (e.getReason()) {
                    case CryptoException.ILLEGAL_VALUE:
                        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        break;
                    case CryptoException.NO_SUCH_ALGORITHM:
                        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
            }
        } while (TlvUtils.getParseLength(parserMetadata, SHORT_0) > 0);

        return 0;
    }

    private short generateAppletKeyPair(byte[] outBuffer, short outOffset) {
        // Acquire handles to all the EC private & public key objects, and ensure all handles are valid
        ECPrivateKey ecPrivateKey = (ECPrivateKey) getTransientECKeyOrThrow(IDX_TRANSIENT_PRIVATE, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        ECPublicKey ecPublicKey = (ECPublicKey) getTransientECKeyOrThrow(IDX_TRANSIENT_PUBLIC, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        ECPrivateKey ecEphPrivateKey = (ECPrivateKey) getTransientECKeyOrThrow(IDX_EPH_TRANSIENT_PRIVATE, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        ECPublicKey ecEphPublicKey = (ECPublicKey) getTransientECKeyOrThrow(IDX_EPH_TRANSIENT_PUBLIC, ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        try {
            // Generate the key pair
            new KeyPair(ecPublicKey, ecPrivateKey).genKeyPair();
            // Write public key into the buffer
            short offset = Util.setShort(outBuffer, outOffset, TAG_PUBLIC_KEY_PARAMS);
            short publicKeyDataLength = ecPublicKey.getW(outBuffer, (short) (offset + 1 + 1 + 1));
            outBuffer[offset++] = (byte) (publicKeyDataLength + 1 + 1);
            outBuffer[offset++] = TAG_EC_CURVE_PUBLIC_KEY;
            outBuffer[offset++] = (byte) publicKeyDataLength;
            offset += publicKeyDataLength;

            // Begin transaction
            JCSystem.beginTransaction();
            // Set the newly generated keys
            this.ecPrivateKey = ecPrivateKey;
            this.ecEphPrivateKey = ecEphPrivateKey;
            this.ecEphPublicKey = ecEphPublicKey;
            // Invalidate the current certificate file, if any
            this.certificateFile = null;
            // Set the applet state to installed with key-pair generated
            lifeCycleState = LIFECYCLE_INSTALLED | LIFECYCLE_KEYPAIR_GENERATED_BIT;
            // Commit transaction
            JCSystem.commitTransaction();

            // Invalidate the transient handles to the keys
            for (byte i = 0; i < transientECKeys.length; i++) {
                setTransientECKey(i, null);
            }
            // Return the length written into the output buffer
            return (short) (offset - outOffset);
        } catch (CryptoException e) {
            // new KeyPair(PublicKey, PrivateKey) - CryptoException.ILLEGAL_VALUE: input parameter key objects are mismatched - different algorithms or different key sizes.
            // new KeyPair(PublicKey, PrivateKey) - CryptoException.NO_SUCH_ALGORITHM: algorithm associated with the specified type, size of key is not supported.
            // KeyPair.genKeyPair() - CryptoException.ILLEGAL_VALUE: pre-initialized Field, A, B, G and R parameter set in public EC key is invalid.
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        } finally {
            JCSystem.requestObjectDeletion();
        }

        return 0; // Make compiler happy
    }

    private short putAppletCertificate(byte[] inBuffer, short inOffset, short inLength) {
        // Ensure the current applet state is one step short from being personalized
        if (lifeCycleState != (LIFECYCLE_PERSONALIZED ^ LIFECYCLE_CERTIFICATE_STORED_BIT)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Use transient memory for parser metadata buffer
        byte[] parserMetadata = clearOnResetTransientMemory;
        // Initialize the parser metadata buffer with the input data offset and length values
        TlvUtils.setParserMetadata(inOffset, inLength, parserMetadata, SHORT_0);

        // Ensure the first TLV tag is INTEGER
        TlvUtils.ensureTlvTag1(TAG_UNIVERSAL_INTEGER, inBuffer, parserMetadata, SHORT_0);
        // Obtain the integer value representing the offset into the certificate file
        short destinationOffset = TlvUtils.parseTlvInteger(inBuffer, parserMetadata, SHORT_0);
        // Ensure the offset is not negative
        if (destinationOffset < SHORT_0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        // Ensure the next TLV tag is OCTET STRING and obtain its length
        inLength = TlvUtils.ensureTlvTag1AndParseLength(TAG_UNIVERSAL_OCTET_STRING, inBuffer, parserMetadata, SHORT_0);
        // Ensure enough input data is available and obtain the offset of that data
        inOffset = TlvUtils.ensureParsableInputAvailable(inLength, parserMetadata, SHORT_0);

        byte[] destinationBuffer = certificateFile;

        if (destinationOffset == 0) {
            // Re-initialize the parser metadata buffer with the offset and length of the incoming certificate data
            TlvUtils.setParserMetadata(inOffset, inLength, parserMetadata, SHORT_0);
            // Ensure the first byte of the certificate is the SEQUENCE tag, and obtain the length of the following data
            short certificateLength = TlvUtils.ensureTlvTag1AndParseLength(TAG_UNIVERSAL_SEQUENCE, inBuffer, parserMetadata, SHORT_0);
            // Take the already parsed portion of the certificate length into account in the overall certificate file length
            certificateLength += (short) (TlvUtils.getParseOffset(parserMetadata, SHORT_0) - inOffset);

            // Ensure the requested file size is in a sane range
            if (certificateLength < MIN_CERTIFICATE_FILE_SIZE || certificateLength > MAX_CERTIFICATE_FILE_SIZE) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Allocate memory for the certificate
            certificateFile = (destinationBuffer = new byte[certificateLength]);
        } else if (destinationBuffer == null || (short) (destinationOffset + inLength) > destinationBuffer.length) {
            // Fail if certificate file does not exist or the write would overflow
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Copy the octet string into the certificate file at the specified offset
        destinationOffset = Util.arrayCopy(inBuffer, inOffset, destinationBuffer, destinationOffset, inLength);
        // If the end of the certificate file has been reached, finalize the certificate storage state
        if (destinationOffset == destinationBuffer.length) {
            lifeCycleState |= LIFECYCLE_CERTIFICATE_STORED_BIT;
        }

        return 0; // Keep the compiler happy
    }

    private short getAppletCertificate(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset, short responseLength) {
        byte[] sourceBuffer = certificateFile;
        // Fail immediately if there is no certificate file
        if (sourceBuffer == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        // Acquire the current length of the source buffer
        short sourceLength = (short) sourceBuffer.length;

        // Use transient memory for parser metadata buffer
        byte[] parserMetadata = clearOnResetTransientMemory;
        // Initialize the parser metadata buffer with the input data offset and length values
        TlvUtils.setParserMetadata(inOffset, inLength, parserMetadata, SHORT_0);

        // Ensure the first TLV tag is INTEGER
        TlvUtils.ensureTlvTag1(TAG_UNIVERSAL_INTEGER, inBuffer, parserMetadata, SHORT_0);
        // Obtain the integer value representing the offset into the certificate file
        short sourceOffset = TlvUtils.parseTlvInteger(inBuffer, parserMetadata, SHORT_0);
        // Ensure the offset is valid
        if (sourceOffset < SHORT_0 || sourceOffset > sourceLength) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Adjust the response length if there are fewer bytes to return than was expected
        if ((sourceLength -= sourceOffset) < responseLength) {
            responseLength = sourceLength;
        }

        Util.arrayCopyNonAtomic(sourceBuffer, sourceOffset, outBuffer, outOffset, responseLength);

        return responseLength;
    }


    /**
     * \brief Get the field length of an EC FP key using the amount of bytes
     * 			of a parameter (e.g. the prime).
     *
     * \return The bit length of the field.
     *
     * \throw ISOException SC_FUNC_NOT_SUPPORTED.
     */
    private static short getEcFpFieldLength(short bytes) {
        switch(bytes) {
            case 14:
                return KeyBuilder.LENGTH_EC_FP_112;
            case 16:
                return KeyBuilder.LENGTH_EC_FP_128;
            case 20:
                return KeyBuilder.LENGTH_EC_FP_160;
            case 24:
                return KeyBuilder.LENGTH_EC_FP_192;
            case 28:
                return KeyBuilder.LENGTH_EC_FP_224;
            case 32:
                return KeyBuilder.LENGTH_EC_FP_256;
            case 40:
                return LENGTH_EC_FP_320;
            case 48:
                return KeyBuilder.LENGTH_EC_FP_384;
            case 64:
                return LENGTH_EC_FP_512;
            case 66:
                return KeyBuilder.LENGTH_EC_FP_521;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                return 0; // Make compiler happy
        }
    }

    // AppletRegistry implementation

    private AID[] registry = new AID[0];

    @Override
    public boolean isRegistered() {
        AID clientAid = JCSystem.getPreviousContextAID();
        for (byte i = 0; i < registry.length; i++) {
            if (clientAid.equals(registry[i])) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void registerApplet() {
        if (isRegistered()) {
            return; // TODO: define a correct exception
        }
        AID clientAid = JCSystem.getPreviousContextAID();
        JCSystem.beginTransaction();

        AID[] newRegistry = new AID[(byte) ((byte) registry.length + (byte) 1)];
        for (byte i = 0; i < registry.length; i++) {
            newRegistry[i] = registry[i];
        }
        newRegistry[registry.length] = clientAid;
        registry = newRegistry;

        JCSystem.commitTransaction();
        JCSystem.requestObjectDeletion();
    }

    @Override
    public void unregisterApplet() {
        if (!isRegistered()) {
            return; // TODO: define a correct exception
        }
        AID clientAid = JCSystem.getPreviousContextAID();
        AID[] newRegistry = new AID[(byte) ((byte) registry.length - (byte) 1)];
        for (byte i = 0, j = 0; i < registry.length; i++) {
            if (!clientAid.equals(registry[i])) {
                newRegistry[j++] = registry[i];
            }
        }
        registry = newRegistry;
        JCSystem.requestObjectDeletion();
    }
}
