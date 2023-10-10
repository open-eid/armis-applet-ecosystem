package ee.openeid.armis.applet.ecosystem.testclient;

import ee.openeid.armis.applet.ecosystem.libs.AbstractApplet;
import ee.openeid.armis.applet.ecosystem.libs.ECDHE;
import ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService;
import ee.openeid.armis.applet.ecosystem.libs.TlvUtils;
import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import org.globalplatform.Personalization;

import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SHORT_0;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SIZE_OF_BYTE;
import static javacard.framework.ISO7816.OFFSET_CDATA;
import static javacard.framework.ISO7816.OFFSET_INS;
import static javacard.framework.ISO7816.OFFSET_LC;
import static javacard.framework.ISO7816.OFFSET_P1;
import static javacard.framework.ISO7816.SW_DATA_INVALID;
import static javacard.framework.ISO7816.SW_INCORRECT_P1P2;
import static javacard.framework.ISO7816.SW_INS_NOT_SUPPORTED;
import static javacard.framework.ISO7816.SW_NO_ERROR;
import static javacard.framework.ISO7816.SW_WRONG_LENGTH;

public class TestClient extends AbstractApplet implements ExtendedLength, Personalization {

    // Clear-on-reset reusable transient buffer size
    // The size of this buffer should be as small as possible since the RAM allocated for CLEAR_ON_RESET buffers is not available to other applets
    private static final short SIZE_BUFFER_CLEAR_ON_RESET = (KeyBuilder.LENGTH_EC_FP_384 / 8) +
                                                            (KeyBuilder.LENGTH_AES_256 / 8);

    private static final short TAG_CARDHOLDER_CERTIFICATE = (short) 0x7F21;
    private static final short TAG_TEXT = (short) 0x7F82;

    // Instance state and all possible state constants
    private byte lifeCycleState;

    private static final byte LIFECYCLE_UNINITIALIZED = (byte) 0;
    private static final byte LIFECYCLE_INSTALLED_BIT = (byte) 0x01;
    private static final byte LIFECYCLE_INSTALLED = LIFECYCLE_INSTALLED_BIT;

    // Reusable clear-on-reset transient buffer
    private final byte[] clearOnResetTransientMemory;

    // Clear on reset transient object
    private final Object[] transientObjects;

    private static final byte IDX_AES_AUTHENTICATION = 0;

    // Secure messaging
    private final Signature ecdsaSha384NoPad;
    private final Cipher cipherAesCbcIso9797M2;
    private final Signature smMac;

    // Persistent memory to hold value of `TAG_TEXT`
    private final byte[] persistentText;
    private short persistentTextLength = 0;

    private static final byte PERSISTENT_TEXT_MAX_LENGTH = 20;

    private static class TestClientFactory implements AppletFactory {
        @Override
        public AbstractApplet create(byte[] bArray, short bOffset, short bLength, byte appletPrivileges, byte[] globalParserMetadata) {
            return new TestClient(bArray, bOffset, bLength, globalParserMetadata);
        }
    }

    // Global Platform Specification 2.2.1
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        install(new TestClientFactory(), bArray, bOffset, bLength);
    }

    @Override
    protected void appletEvent(byte event) {
        if (event == APPLET_EVENT_REGISTERED && lifeCycleState == LIFECYCLE_UNINITIALIZED) {
            // Do nothing
        } else if (event == APPLET_EVENT_INSTALLED && lifeCycleState == LIFECYCLE_UNINITIALIZED) {
            // Mark the applet as installed
            lifeCycleState = LIFECYCLE_INSTALLED;
        }
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        short responseLength = 0;
        byte INS = buffer[OFFSET_INS];

        try {
            switch (INS) {
                case INS_GET_DATA:
                    responseLength = getData(apdu);
                    break;
                default: ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException ex) {
            sendResponse(apdu, responseLength, INS, ex.getReason());
            throw ex;
        }

        sendResponse(apdu, responseLength, INS, SW_NO_ERROR);
    }

    void sendResponse(APDU apdu, short responseLength, byte INS, short statusWord) {
        byte[] buffer = apdu.getBuffer();

        responseLength = wrapSecureIfPossible(responseLength, INS, buffer, SHORT_0, statusWord);
        apdu.setOutgoingLength(responseLength);
        if (isExtendedAPDU(apdu)) {
            apdu.sendBytesLong(buffer, (short) 0, responseLength);
        } else {
            apdu.sendBytes((short) 0, responseLength);
        }
    }

    @Override
    @SuppressWarnings("fallthrough")
    public short processData(boolean isLastOrOnly, byte encryption, byte dataStructure, boolean isResponseExpected, short sequence, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {

        // Use global transient memory for parser metadata buffer
        byte[] globalParserMetadata = TlvUtils.getNewGlobalMetadata();
        // Initialize the parser metadata buffer with the input data offset and length values
        TlvUtils.setParserMetadata(inOffset, inLength, globalParserMetadata, SHORT_0);
        // Ensure the input is long enough and skip to the beginning of the nested command
        TlvUtils.ensureParsableInputAvailable(OFFSET_CDATA, globalParserMetadata, SHORT_0);
        // Ensure the input is long enough and acquire the offset of nested INS byte
        short apduInsP1P2LcDataLength = TlvUtils.getParseLength(globalParserMetadata, SHORT_0);
        short apduInsOffset = TlvUtils.ensureParsableInputAvailable(TlvUtils.SIZE_OF_BYTE, globalParserMetadata, SHORT_0);
        short outLength = 0;

        byte INS = inBuffer[apduInsOffset];
        if (INS == INS_INTERNAL_AUTHENTICATE) return internalAuthenticate(inBuffer, (short) (inOffset + OFFSET_CDATA + OFFSET_NESTED_CDATA), (short) (inLength - OFFSET_CDATA - OFFSET_NESTED_CDATA), outBuffer, outOffset);
        short lengthDiff = (short) (apduInsP1P2LcDataLength - (apduInsP1P2LcDataLength = unwrap(true, cipherAesCbcIso9797M2, getAESKey(), smMac, getAESKey(), inBuffer, apduInsOffset, apduInsP1P2LcDataLength)) - OFFSET_NESTED_P1);
        TlvUtils.setParseLength((short) (TlvUtils.getParseLength(globalParserMetadata, SHORT_0) - lengthDiff), globalParserMetadata, SHORT_0);
        inBuffer[(short) (inOffset + OFFSET_LC)] = (byte) (apduInsP1P2LcDataLength & 0xFF);
        switch (INS) {
            case INS_GET_DATA:
            case INS_GET_DATA2:
            case INS_PUT_DATA:
                // Acquire the 2-byte data identifier tag
                short tag = TlvUtils.parseTlvTag2(inBuffer, globalParserMetadata, SHORT_0);
                // Skip nested Lc element
                short Lc = TlvUtils.parseTlvInteger(SIZE_OF_BYTE, inBuffer, globalParserMetadata, SHORT_0);
                inOffset = TlvUtils.getParseOffset(globalParserMetadata, SHORT_0);
                if (INS == INS_GET_DATA) {
                    if (!isResponseExpected) ISOException.throwIt(SW_DATA_INVALID);
                    if (apduInsP1P2LcDataLength != 3) ISOException.throwIt(SW_DATA_INVALID);
                    short Le = Util.makeShort((byte) 0, inBuffer[(short) (apduInsOffset + OFFSET_LC)]);

                    switch (tag) {
                        case TAG_CARDHOLDER_CERTIFICATE: outLength = getCertificate(SHORT_0, outBuffer, outOffset, Le); break;
                        case TAG_TEXT: outLength = getText(outBuffer, outOffset); break;
                        default: ISOException.throwIt(SW_DATA_INVALID);
                    }
                    break;
                } else if (INS == INS_GET_DATA2) {
                    if (!isResponseExpected) ISOException.throwIt(SW_DATA_INVALID);
                    short offsetLength = TlvUtils.ensureTlvTag1AndParseLength((byte) 0x5C, inBuffer, globalParserMetadata, SHORT_0);
                    if (offsetLength > 2) ISOException.throwIt(SW_DATA_INVALID);
                    short offsetGetData = TlvUtils.parseTlvInteger(offsetLength, inBuffer, globalParserMetadata, SHORT_0);
                    short LeLength = TlvUtils.getParseLength(globalParserMetadata, SHORT_0);
                    if (offsetGetData < 0 || LeLength > 1) ISOException.throwIt(SW_DATA_INVALID);
                    short Le = LeLength == 1
                            // TODO: Check whether this actually works.
                            //  Currently values larger than 127 are not supported!
                            ? TlvUtils.parseTlvInteger(LeLength, inBuffer, globalParserMetadata, SHORT_0)
                            : 0;

                    switch (tag) {
                        case TAG_CARDHOLDER_CERTIFICATE: outLength = getCertificate(offsetGetData, outBuffer, outOffset, Le); break;
                        default: ISOException.throwIt(SW_DATA_INVALID);
                    }
                    break;
                } else if (INS == INS_PUT_DATA) {
                    // PUT_DATA must not enforce no response expected, because with secure messaging there is always a response!
                    switch (tag) {
                        case TAG_TEXT: outLength = putText(inBuffer, inOffset, Lc); break;
                        default: ISOException.throwIt(SW_DATA_INVALID);
                    }
                    break;
                }
            default: ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        return wrap(true, cipherAesCbcIso9797M2, getAESKey(), smMac, getAESKey(), INS, outBuffer, outOffset, outLength, SW_NO_ERROR);
    }

    @Override
    protected boolean isAuthenticated() {
        return getAESKey() != null;
    }

    @Override
    protected void flushAuthentication() {
        transientObjects[IDX_AES_AUTHENTICATION] = null;
    }

    private AESKey getAESKey() {
        return (AESKey) transientObjects[IDX_AES_AUTHENTICATION];
    }

    private void setAesKey(AESKey aesKey) {
        transientObjects[IDX_AES_AUTHENTICATION] = aesKey;
    }

    private short unwrapSecureIfPossible(byte[] apduBuffer, short apduInsOffset, short apduInsP1P2LcDataLength) {
        if (apduInsP1P2LcDataLength > 0) {
            cipherAesCbcIso9797M2.init(getAESKey(), Cipher.MODE_DECRYPT);
            // smMac.init(getAESKey(), Cipher.MODE_ENCRYPT); // TODO: Secure Messaging MAC
            return unwrap(isAuthenticated(), cipherAesCbcIso9797M2, smMac, apduBuffer, apduInsOffset, apduInsP1P2LcDataLength);
        }
        return apduInsP1P2LcDataLength;
    }

    private short wrapSecureIfPossible(short rapduLength, byte INS, byte[] rapduBuffer, short rapduOffset, short statusWord) {
        if (isAuthenticated()) {
            cipherAesCbcIso9797M2.init(getAESKey(), Cipher.MODE_ENCRYPT);
            // smMac.init(getAESKey(), Cipher.MODE_ENCRYPT); // TODO: Secure Messaging MAC
            return wrap(isAuthenticated(), cipherAesCbcIso9797M2, smMac, INS, rapduBuffer, rapduOffset, rapduLength, statusWord);
        }
        return rapduLength;
    }

    private TestClient(byte[] bArray, short bOffset, short bLength, byte[] globalParserMetadata) {
        super(bArray, globalParserMetadata);
        if (TlvUtils.getParseLength(globalParserMetadata, SHORT_0) != 0) {
            // All the input data should be read by now
            ISOException.throwIt(SW_DATA_INVALID);
        }
        lifeCycleState = LIFECYCLE_UNINITIALIZED;
        persistentText = new byte[PERSISTENT_TEXT_MAX_LENGTH];
        clearOnResetTransientMemory = JCSystem.makeTransientByteArray(SIZE_BUFFER_CLEAR_ON_RESET, JCSystem.CLEAR_ON_RESET);
        transientObjects = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
        cipherAesCbcIso9797M2 = Cipher.getInstance(Cipher.CIPHER_AES_CBC, Cipher.PAD_ISO9797_M2, false);
        // `Signature.ALG_AES_CMAC_128` is introduced in JavaCard 3.0.5 and is missing from 3.0.4
        smMac = null/*Signature.getInstance(MessageDigest.ALG_NULL,  Signature.SIG_CIPHER_AES_CMAC128, Cipher.PAD_ISO9797_M2, false)*/; // TODO: Secure Messaging MAC
        ecdsaSha384NoPad = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
    }

    private short getData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short Lc = apdu.setIncomingAndReceive();
        Lc = unwrapSecureIfPossible(buffer, SHORT_0, Lc);
        short Le = apdu.setOutgoing();
        // Decide on P1 and P2
        switch (Util.getShort(buffer, OFFSET_P1)) {
            case TAG_CARDHOLDER_CERTIFICATE: return getCertificate(SHORT_0, buffer, SHORT_0, Le);
            default: ISOException.throwIt(SW_INCORRECT_P1P2);
        }
        return 0;
    }

    private short putText(byte[] inBuffer, short inOffset, short inLength) {
        if (inLength > PERSISTENT_TEXT_MAX_LENGTH) ISOException.throwIt(SW_WRONG_LENGTH);
        Util.arrayCopyNonAtomic(inBuffer, inOffset, persistentText, SHORT_0, inLength);
        persistentTextLength = inLength;
        return 0;
    }

    private short getText(byte[] outBuffer, short outOffset) {
        Util.arrayCopyNonAtomic(persistentText, SHORT_0, outBuffer, outOffset, persistentTextLength);
        return persistentTextLength;
    }

    // TODO: Move internalAuthenticate implementation to AbstractApplet.
    private short internalAuthenticate(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        byte[] globalParserMetadata = TlvUtils.getNewGlobalMetadata();
        TlvUtils.setParserMetadata(inOffset, inLength, globalParserMetadata, SHORT_0);
        // SEQUENCE ::= {
        //      ecPubPoint OCTET STRING,
        //      ecdsaSignature SEQUENCE ::= { r INTEGER, s INTEGER }
        // }
        short sequenceSize = TlvUtils.ensureTlvTag1AndParseLength((byte) 0x30, inBuffer, globalParserMetadata, SHORT_0);
        short sequenceOffset = TlvUtils.getParseOffset(globalParserMetadata, SHORT_0);
        short ecEphmPublicKeyLength = TlvUtils.ensureTlvTag1AndParseLength((byte) 0x04, inBuffer, globalParserMetadata, SHORT_0);
        short ecEphmPublicKeyOffset = TlvUtils.ensureParsableInputAvailable(ecEphmPublicKeyLength, globalParserMetadata, SHORT_0);
        // Nested ASN.1 signature SEQUENCE ::= { r INTEGER, s INTEGER }
        short signatureAsn1Length = (short) (sequenceSize - (short) (TlvUtils.getParseOffset(globalParserMetadata, SHORT_0) - sequenceOffset));
        short signatureAsn1Offset = TlvUtils.ensureTlvTag1((byte) 0x30, inBuffer, globalParserMetadata, SHORT_0);

        try {
            ecdsaSha384NoPad.init(issuerPublicKey, Signature.MODE_VERIFY);
            if (!ecdsaSha384NoPad.verify(inBuffer, ecEphmPublicKeyOffset, ecEphmPublicKeyLength, inBuffer, signatureAsn1Offset, signatureAsn1Length)) {
                ISOException.throwIt(SW_DATA_INVALID); // TODO: is it the correct SW?
            }

            ECPrivateKeyService ecPrivateKeyService = getEcPrivateKeyService();
            ECDHE ecdhe = ecPrivateKeyService.performEcdhe(inBuffer, inOffset, inLength);
            setAesKey((AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false));
            short aesKeySize = (short) (KeyBuilder.LENGTH_AES_256 / 8);
            short secretOffset = SHORT_0;
            short secretLength = ecdhe.getSecret(null, SHORT_0);
            byte[] secret = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, secretLength);
            ecdhe.getSecret(secret, SHORT_0);
            short aesKeyOffset = Util.arrayCopyNonAtomic(secret, SHORT_0, clearOnResetTransientMemory, secretOffset, secretLength);

            concatKDF.init(clearOnResetTransientMemory, secretOffset, secretLength, null, SHORT_0, SHORT_0);
            concatKDF.generate(clearOnResetTransientMemory, aesKeyOffset, aesKeySize);
            getAESKey().setKey(clearOnResetTransientMemory, aesKeyOffset);

            return ecdhe.getSignedEphemeralPublicKey(outBuffer, outOffset);
        } catch (ISOException ex) {
            flushAuthentication();
            throw ex;
        }
    }
}
