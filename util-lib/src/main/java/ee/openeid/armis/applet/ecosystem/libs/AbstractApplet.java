package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import org.globalplatform.Personalization;

import static ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService.TAG_EC_CURVE_COFACTOR;
import static ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService.TAG_EC_CURVE_COMPONENT_A;
import static ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService.TAG_EC_CURVE_COMPONENT_B;
import static ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService.TAG_EC_CURVE_GENERATOR;
import static ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService.TAG_EC_CURVE_ORDER;
import static ee.openeid.armis.applet.ecosystem.libs.ECPrivateKeyService.TAG_EC_CURVE_PRIME;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.BYTE_0;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SHORT_0;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SIZE_OF_BYTE;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SIZE_OF_SHORT;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.getNewGlobalMetadata;
import static javacard.framework.ISO7816.OFFSET_CDATA;
import static javacard.framework.ISO7816.OFFSET_EXT_CDATA;
import static javacard.framework.ISO7816.OFFSET_INS;
import static javacard.framework.ISO7816.OFFSET_LC;
import static javacard.framework.ISO7816.OFFSET_P1;
import static javacard.framework.ISO7816.OFFSET_P2;
import static javacard.framework.ISO7816.SW_DATA_INVALID;
import static javacard.framework.ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
import static javacard.framework.ISO7816.SW_WRONG_DATA;

public abstract class AbstractApplet extends Applet implements AppletEvent, Personalization {

    // INS declarations
    public static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_GET_DATA2 = (byte) 0xCB;
    public static final byte INS_PUT_DATA = (byte) 0xDA;

    // Status words
    public static final short SW_INCORRECT_SECURE_MESSAGING = 0x6988;

    // Applet events
    public static final byte APPLET_EVENT_REGISTERED = 0x11;
    public static final byte APPLET_EVENT_INSTALLED = 0x12;

    // AID minimum and maximum indicator constants
    protected static final short AID_MIN_SIZE = 5;
    protected static final short AID_MAX_SIZE = 16;

    // INSTALL [for personalization] nested APDU offsets
    public static final byte OFFSET_NESTED_HEADER = -1;
    public static final byte OFFSET_NESTED_INS = OFFSET_INS + OFFSET_NESTED_HEADER;
    public static final byte OFFSET_NESTED_P1 = OFFSET_P1 + OFFSET_NESTED_HEADER;
    public static final byte OFFSET_NESTED_P2 = OFFSET_P2 + OFFSET_NESTED_HEADER;
    public static final byte OFFSET_NESTED_LC = OFFSET_LC + OFFSET_NESTED_HEADER;
    public static final byte OFFSET_NESTED_CDATA = OFFSET_CDATA + OFFSET_NESTED_HEADER;

    // INSTALL [for personalization] encryption specifier
    public static final byte STORE_DATA_ENCRYPTION_UNSPECIFIED = 0x00;
    public static final byte STORE_DATA_ENCRYPTION_APPLET_DEPENDENT = 0x01;
    public static final byte STORE_DATA_ENCRYPTION_RFU = 0x02;
    public static final byte STORE_DATA_ENCRYPTION_ENCRYPTED = 0x03;

    // Secure Messaging structure tags
    public static final byte TAG_SM_DATA_EVEN_INS = (byte) 0x86;
    public static final byte TAG_SM_DATA_USE_IN_MAC_EVEN_INS = (byte) 0x87;
    public static final byte PAD_INDICATOR_BYTE = 1;
    public static final byte PAD_INDICATOR_SM_DATA_EVEN_INS = (byte) 0x01;
    public static final byte TAG_SM_DATA_ODD_INS = (byte) 0x84;
    public static final byte TAG_SM_DATA_USE_IN_MAC_ODD_INS = (byte) 0x85;
    public static final byte TAG_SM_LE = (byte) 0x97;
    public static final byte TAG_SM_MAC = (byte) 0x8E;
    public static final byte TAG_SM_STATUS_WORD = (byte) 0x99;

    private AppletRegistry appletRegistry;
    private ECPrivateKeyService ecPrivateKeyService;
    protected final MessageDigest digestSha384;
    protected final ConcatKDF concatKDF;

    protected final ECPublicKey issuerPublicKey;
    protected byte[] issuerPublicKeySha384Compare;

    protected interface AppletFactory {
        AbstractApplet create(byte[] bArray, short bOffset, short bLength, byte appletPrivileges, byte[] globalParserMetadata);
    }

    /**
     * @param bArray buffer containing the applet installation payload
     * @param globalParserMetadata reusable buffer containing the current offset and length for parsing the LV (length and value)
     *                             of the digest of the applet installation finalization payload from bArray
     * @throws CryptoException if parsed length does not correspond to the length of SHA384 hash
     */
    protected AbstractApplet(byte[] bArray, byte[] globalParserMetadata) throws CryptoException {
        // Require object deletion support on this device
        if (!JCSystem.isObjectDeletionSupported()) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        short bLength = TlvUtils.parseTlvLength(bArray, globalParserMetadata, SHORT_0);
        if (bLength != MessageDigest.LENGTH_SHA_384) ISOException.throwIt(SW_DATA_INVALID);
        short bOffset = TlvUtils.ensureParsableInputAvailable(bLength, globalParserMetadata, SHORT_0);

        issuerPublicKeySha384Compare = new byte[(short) (bLength * 2)];
        Util.arrayCopyNonAtomic(bArray, bOffset, issuerPublicKeySha384Compare, SHORT_0, bLength);
        issuerPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_384, false);
        digestSha384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
        concatKDF = new ConcatKDF(digestSha384);
    }

    /**
     * Parses the applet installation parameters, creates the applet instance and
     * registers it with the Java Card runtime environment and the manager applet.
     *
     * For the reference of the structure of the contents of the applet
     * installation parameters in the bArray, see the description of the
     * Java Card {@link Applet#install(byte[], short, byte)} method.
     *
     * The applet-specific payload in the applet installation parameters has the following structure:
     *  - The length of the AID of ARMIS manager applet (1 byte)
     *  - The bytes of the AID of ARMIS manager applet
     *  - The length of the hash of issuer's public key (1 byte)
     *  - The bytes of the hash of issuer's public key (must be an SHA-384 hash)
     *
     * @param appletFactory factory instance for creating specific type of Applet
     * @param bArray buffer containing the applet installation payload
     * @param bOffset offset of the applet installation payload in bArray
     * @param bLength length of the applet installation payload in bArray
     */
    protected final static void install(AppletFactory appletFactory, byte[] bArray, short bOffset, byte bLength) {
        try {
            byte[] globalParserMetadata = TlvUtils.getNewGlobalMetadata();

            TlvUtils.setParserMetadata(bOffset, bLength, globalParserMetadata, SHORT_0);
            // GlobalPlatform Card Specification Version 2.2.1 - Table 11-49: Install Parameter Tags. Content of tag 0x9C.
            // Instance aid
            short instanceAidLength = TlvUtils.parseTlvLength(bArray, globalParserMetadata, SHORT_0);
            if (instanceAidLength > AID_MAX_SIZE || (0 < instanceAidLength && instanceAidLength < AID_MIN_SIZE)) {
                SystemException.throwIt(SystemException.ILLEGAL_AID);
            }
            short instanceAidOffset = TlvUtils.ensureParsableInputAvailable(instanceAidLength, globalParserMetadata, SHORT_0);
            // Applet privileges
            short elementLength = TlvUtils.parseTlvLength(bArray, globalParserMetadata, SHORT_0);
            // TODO Privileges can be 1 or 3 bytes.
            if (elementLength != (short) 1) ISOException.throwIt(SW_DATA_INVALID);
            byte appletPrivileges = (byte) (TlvUtils.parseTlvInteger(SIZE_OF_BYTE, bArray, globalParserMetadata, SHORT_0) & 0xFF);
            // ARMIS Applet Payload
            elementLength = TlvUtils.parseTlvLength(bArray, globalParserMetadata, SHORT_0);
            if (elementLength != TlvUtils.getParseLength(globalParserMetadata, SHORT_0)) ISOException.throwIt(SW_DATA_INVALID);
            // ARMIS Manager AID
            elementLength = TlvUtils.parseTlvLength(bArray, globalParserMetadata, SHORT_0);
            if (elementLength < AID_MIN_SIZE  || AID_MAX_SIZE < elementLength) {
                SystemException.throwIt(SystemException.ILLEGAL_AID);
            }
            AID managerAID = JCSystem.lookupAID(bArray, TlvUtils.ensureParsableInputAvailable(elementLength, globalParserMetadata, SHORT_0), (byte) (elementLength & 0xFF));
            if (managerAID == null) {
                SystemException.throwIt(SystemException.ILLEGAL_AID);
            }

            AbstractApplet instance = appletFactory.create(bArray, bOffset, bLength, appletPrivileges, globalParserMetadata);

            // Check if explicit instance AID is present in the payload
            if (instanceAidLength > 0) {
                // Register the applet using the specified instance AID
                instance.registerApplet(bArray, instanceAidOffset, (byte) instanceAidLength, managerAID);
            } else {
                // Register the applet using default AID
                instance.registerApplet(managerAID);
            }
        } finally {
            // Not sure if it makes any difference. Somehow the memory resources allocated for `AppletFactory` need to be released.
            appletFactory = null;
            JCSystem.requestObjectDeletion();
        }
    }

    protected final ECPrivateKeyService getEcPrivateKeyService() {
        return ecPrivateKeyService;
    }

    /**
     * Register this applet with the Java Card runtime environment and the manager applet.
     * The name of the applet is assigned as its instance AID bytes.
     * @param managerAID AID of manager applet
     * @throws SystemException if the Applet's AID bytes are in use or if the applet has already been registered with
     *                         the Java Card runtime environment or if install() method has not been initiated
     */
    protected final void registerApplet(AID managerAID) throws SystemException {
        register();
        registerInternal(managerAID);
    }


    /**
     * Register this applet with the Java Card runtime environment and the manager applet.
     * Specified AID bytes are assigned as its instance AID bytes.
     * @param bArray byte array containing the AID bytes
     * @param instanceAidOffset start offset of AID bytes in bArray
     * @param instanceAidLength the length of AID bytes in bArray
     * @param managerAID AID of manager applet
     * @throws SystemException if the Applet's AID bytes are in use or if the applet has already been registered with
     *                         the Java Card runtime environment or if install() method has not been initiated
     */
    protected final void registerApplet(byte[] bArray, short instanceAidOffset, byte instanceAidLength, AID managerAID) throws SystemException {
        register(bArray, instanceAidOffset, instanceAidLength);
        registerInternal(managerAID);
    }

    private void registerInternal(AID managerAID) {
        Shareable managerApplet = JCSystem.getAppletShareableInterfaceObject(managerAID, BYTE_0);
        appletRegistry = (AppletRegistry) managerApplet;
        ecPrivateKeyService = (ECPrivateKeyService) managerApplet;
        copyDomainParametersFrom(ecPrivateKeyService, issuerPublicKey, (short) (1 + ((short) (issuerPublicKey.getSize() >> 3) << 1)));
        JCSystem.requestObjectDeletion();
        appletRegistry.registerApplet();
        appletEvent(APPLET_EVENT_REGISTERED);
    }

    /**
     * A callback function to be executed when the applet reaches state APPLET_EVENT_REGISTERED or APPLET_EVENT_INSTALLED
     * @param event applet event
     */
    protected void appletEvent(byte event) {
        // Could be implemented by the subclass
    }

    /**
     * This method should be overridden if any cleaning needs to be performed by the applet before uninstall.
     * <b>Notes from :</b>
     * <ul>
     *     <li>Exceptions thrown by this method are caught by the Java Card runtime environment and ignored.</li>
     *     <li>The Java Card runtime environment will not rollback state automatically if applet deletion fails.</li>
     *     <li>This method may be called by the Java Card runtime environment multiple times, once for each attempt to delete this applet instance.</li>
     * </ul>
     * @see <a href="https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/AppletEvent.html#uninstall()">Java Card API v3.0.5: javacard.framework.AppletEvent.uninstall()</a>
     * @see <a href="https://docs.oracle.com/javacard/3.0.5/prognotes/appletevent-uninstall-method.htm">Java Card 3 Platform Programming Notes: The AppletEvent.uninstall Method</a>
     */
    protected void uninstallingApplet()  {};

    /**
     * @see <a href="https://docs.oracle.com/javacard/3.0.5/api/javacard/framework/AppletEvent.html#uninstall()">Java Card API v3.0.5: javacard.framework.AppletEvent.uninstall()</a>
     */
    @Override
    public final void uninstall() {
        if (appletRegistry != null && appletRegistry.isRegistered()) {
            try {
                uninstallingApplet();
            } finally {
                appletRegistry.unregisterApplet();
                appletRegistry = null;
                ecPrivateKeyService = null;
                issuerPublicKeySha384Compare = null;
            }
        }
    }

    /**
     * Retrieve the certificate of the {@code ECPrivateKeyService} by calling {@link ECPrivateKeyService#getCertificate(short, byte[], short, short)}.
     * @param bSourceOffset offset of the certificate in the source byte array
     * @param bTargetArray destination buffer where to write the bytes of the certificate file into, or null if only
     *                     the length of the certificate file is needed
     * @param bTargetOffset offset in bTargetArray where to start writing the certificate file bytes from
     * @param bTargetLength maximum number of bytes to write into bTargetArray. If 0, then the maximum number of bytes will be
     *                      the maximum number that can be represented by short primitive.
     * @return the number of bytes written into bTargetArray, or total length of the certificate file minus
     *         bSourceOffset in case bTargetArray is null
     */
    protected short getCertificate(short bSourceOffset, byte[] bTargetArray, short bTargetOffset, short bTargetLength) {
        if (bTargetLength == 0) bTargetLength = Short.MAX_VALUE;
        return ecPrivateKeyService.getCertificate(bSourceOffset, bTargetArray, bTargetOffset, bTargetLength);
    }

    /**
     * All the incoming processData commands which are not related to finalizing installation
     * will be redirected to this method.
     * @param isLastOrOnly whether the command is the last one in the row
     * @param encryption command data encryption type
     * @param dataStructure command data structure type
     * @param isResponseExpected whether the command should respond with data
     * @param sequence the sequence number of the command
     * @param inBuffer source byte array
     * @param inOffset offset where to start reading the source byte array
     * @param inLength length of the data in source byte array
     * @param outBuffer target byte array
     * @param outOffset offset where to start writing in the target byte array
     * @return length of the data in target byte array
     */
    protected abstract short processData(boolean isLastOrOnly, byte encryption, byte dataStructure, boolean isResponseExpected, short sequence, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);

    /**
     * Processes application specific data received from another entity on the card. If this other entity is the
     * application's associated Security Domain, this data is the APDU buffer.
     * Exceptions thrown are application specific.
     *
     * @param inBuffer the source byte array containing the data expected by the applet. This buffer must be global.
     * @param inOffset starting offset within the source byte array
     * @param inLength length of data
     * @param outBuffer the out byte array where the data expected by the Off-Card Entity shall be set. This buffer shall be global.
     * @param outOffset starting offset within the out byte array
     * @return The number of bytes set in outBuffer at outOffset
     */
    @Override
    public final short processData(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        byte p1 = inBuffer[(byte) (inOffset + OFFSET_P1)];

        // Is installation finalize required?
        if (issuerPublicKeySha384Compare != null && !issuerPublicKey.isInitialized()) {
            return finalizeInstall(
                    /** Buffer references */
                    inBuffer, inOffset, inLength,
                    /** The most significant bit of P1 parameter declares if the command is the last one in the row */
                    (p1 & 0x80) == 0x80,
                    /** The least significant bit of P1 parameter declares if the command should respond with data */
                    (p1 & 0x01) == 0x01);
        }

        return processData(
                /** The most significant bit of P1 parameter declares if the command is the last one in the row */
                (p1 & 0x80) == 0x80,
                /** The P1 parameter's b7-b6 declare the command data encryption type */
                (byte) ((p1 & 0x60) >> 5),
                /** The P1 parameter's b5-b4 declare if the command data structure type */
                (byte) ((p1 & 0x18) >> 3),
                /** The least significant bit of P1 parameter declares if the command should respond with data */
                (p1 & 0x01) == 0x01,
                /** The calue of P2 declares the sequence number of the command */
                Util.makeShort((byte) 0, inBuffer[(byte) (inOffset + OFFSET_P2)]),
                /** Buffer references */
                inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    private short finalizeInstall(byte[] inBuffer, short inOffset, short inLength, boolean isLast, boolean isResponseExpected) {
        if (!isLast || isResponseExpected) ISOException.throwIt(SW_WRONG_DATA);

        // Update offset and remaining length
        inOffset += OFFSET_LC;
        inLength -= OFFSET_CDATA;
        // Ensure there is something to process and update length to process
        if (inLength < (inLength = (short) (inBuffer[inOffset++] & 0xFF))) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // Validate the payload to have the expected data
        digestSha384.doFinal(inBuffer, inOffset, inLength, issuerPublicKeySha384Compare, digestSha384.getLength());
        if (Util.arrayCompare(issuerPublicKeySha384Compare, SHORT_0, issuerPublicKeySha384Compare, MessageDigest.LENGTH_SHA_384, MessageDigest.LENGTH_SHA_384) != 0) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // Assign the key from the payload
        JCSystem.beginTransaction();
        try {
            issuerPublicKey.setW(inBuffer, inOffset, inLength);
        } catch (CryptoException ex) {
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // Clean and release temporary buffer
        Util.arrayFillNonAtomic(issuerPublicKeySha384Compare, SHORT_0, (short) issuerPublicKeySha384Compare.length, BYTE_0);
        issuerPublicKeySha384Compare = null;
        JCSystem.requestObjectDeletion();
        appletEvent(APPLET_EVENT_INSTALLED);
        JCSystem.commitTransaction();

        return 0;
    }

    /**
     * Checks whether the specified APDU is extended APDU.
     * @param apdu APDU to check
     * @return whether the specified APDU is extended APDU
     */
    public static final boolean isExtendedAPDU(APDU apdu) {
        return apdu.getOffsetCdata() == OFFSET_EXT_CDATA;
    }

    /**
     * @return whether the application is in authenticated state
     */
    protected abstract boolean isAuthenticated();

    /**
     * Removes authenticated state from the application
     */
    protected abstract void flushAuthentication();

    /**
     * Decrypts encrypted APDU received from host and returns the length of decrypted data. If doUnwrap == false,
     * the data will not be decrypted and the length of encrypted data will be returned instead.
     * @param doUnwrap whether APDU should actually be decrypted
     * @param smCipher secure messaging cipher implementation
     * @param cipherKey secure messaging cipher key
     * @param smMac secure messaging MAC
     * @param signatureKey secure messaging signature key
     * @param apduBuffer byte array buffer containing encrypted APDU. After running the function, it will contain decrypted APDU.
     * @param apduInsOffset INS parameter offset in apduBuffer
     * @param apduInsP1P2LcDataLength total length of INS, P1, P2 and Lc data in encrypted APDU
     * @return total length of APDU's INS, P1, P2 and Lc data in apduBuffer
     */
    protected short unwrap(boolean doUnwrap, Cipher smCipher, Key cipherKey, Signature smMac, Key signatureKey, byte[] apduBuffer, short apduInsOffset, short apduInsP1P2LcDataLength) {
        if (doUnwrap) {
            if (!isAuthenticated()) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

            smCipher.init(cipherKey, Cipher.MODE_DECRYPT);
            // smMac.init(signatureKey, Signature.MODE_VERIFY); // TODO: Secure Messaging MAC
            return unwrap(doUnwrap, smCipher, smMac, apduBuffer, apduInsOffset, apduInsP1P2LcDataLength);
        }
        return apduInsP1P2LcDataLength;
    }

    /**
     * Decrypts encrypted APDU received from host and returns the length of decrypted data. If doUnwrap == false,
     * the data will not be decrypted and the length of encrypted data will be returned instead.
     * @param doUnwrap whether APDU should actually be decrypted
     * @param cipher secure messaging cipher implementation
     * @param signature secure messaging signature
     * @param apduBuffer byte array buffer containing encrypted APDU. After running the function, it will contain decrypted APDU.
     * @param apduInsOffset INS parameter offset in apduBuffer
     * @param apduInsP1P2LcDataLength total length of INS, P1, P2 and Lc data in encrypted APDU
     * @return total length of APDU's INS, P1, P2 and Lc data in apduBuffer
     */
    protected short unwrap(boolean doUnwrap, Cipher cipher, Signature signature, byte[] apduBuffer, short apduInsOffset, short apduInsP1P2LcDataLength) {
        if (doUnwrap) {
            if (!isAuthenticated()) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            try {
                try {
                    return unwrapStatic(doUnwrap, cipher, signature, apduBuffer, apduInsOffset, apduInsP1P2LcDataLength);
                } catch (CryptoException ex) {
                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            } catch (ISOException ex) {
                flushAuthentication();
                throw ex;
            }
        }
        return apduInsP1P2LcDataLength;
    }

    /**
     * Decrypts encrypted APDU received from host and returns the length of decrypted data. If doUnwrap == false,
     * the data will not be decrypted and the length of encrypted data will be returned instead.
     * @param doUnwrap whether APDU should actually be decrypted
     * @param cipher secure messaging cipher implementation
     * @param signature secure messaging signature
     * @param apduBuffer byte array buffer containing encrypted APDU. After running the function, it will contain decrypted APDU.
     * @param apduInsOffset INS parameter offset in apduBuffer
     * @param apduInsP1P2LcDataLength total length of INS, P1, P2 and Lc data in encrypted APDU
     * @return total length of APDU's INS, P1, P2 and Lc data in apduBuffer
     */
    public static short unwrapStatic(boolean doUnwrap, Cipher cipher, Signature signature, byte[] apduBuffer, short apduInsOffset, short apduInsP1P2LcDataLength) {
        if (doUnwrap) {
            if (apduInsP1P2LcDataLength <= 0 || cipher == null) {
                ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
            }
            byte[] globalParserMetadata = getNewGlobalMetadata();
            try {
                TlvUtils.setParserMetadata(apduInsOffset, apduInsP1P2LcDataLength, globalParserMetadata, SHORT_0);
                byte INS = TlvUtils.parseTlvTag1(apduBuffer, globalParserMetadata, SHORT_0);
                /* skip P1P2 */ TlvUtils.ensureParsableInputAvailable(SIZE_OF_SHORT, globalParserMetadata, SHORT_0);
                short LcOffset = TlvUtils.getParseOffset(globalParserMetadata, SHORT_0);
                short Lc = TlvUtils.parseTlvInteger(SIZE_OF_BYTE, apduBuffer, globalParserMetadata, SHORT_0);
                short LcDataOffset = TlvUtils.getParseOffset(globalParserMetadata, SHORT_0);
                if ((short) (apduInsP1P2LcDataLength - (short) (LcDataOffset - apduInsOffset)) != Lc) ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);

                short nextTlvOffset = TlvUtils.getParseOffset(globalParserMetadata, SHORT_0);
                byte nextTlvTag = TlvUtils.parseTlvTag1(apduBuffer, globalParserMetadata, SHORT_0);

                // EDFB - Encrypted Data Formatted Block
                short edfbTlvOffset = 0, edfbTlvLength = 0, edfbLength = 0, edfbOffset = 0;
                if (nextTlvTag == TAG_SM_DATA_USE_IN_MAC_ODD_INS ||
                    nextTlvTag == TAG_SM_DATA_USE_IN_MAC_EVEN_INS) {
                    edfbTlvOffset = nextTlvOffset;
                    edfbLength = TlvUtils.parseTlvLength(apduBuffer, globalParserMetadata, SHORT_0);
                    boolean isOddINS = (INS & 0x01) == 0x01;
                    if (nextTlvTag == TAG_SM_DATA_USE_IN_MAC_EVEN_INS && !isOddINS && PAD_INDICATOR_SM_DATA_EVEN_INS == TlvUtils.parseTlvInteger(SIZE_OF_BYTE, apduBuffer, globalParserMetadata, SHORT_0)) {
                        edfbLength--;
                    } else if (nextTlvTag == TAG_SM_DATA_USE_IN_MAC_EVEN_INS || !isOddINS) {
                        ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
                    }
                    edfbOffset = TlvUtils.ensureParsableInputAvailable(edfbLength, globalParserMetadata, SHORT_0);
                    edfbTlvLength = (short) (TlvUtils.getParseOffset(globalParserMetadata, SHORT_0) - edfbTlvOffset);

                    nextTlvOffset = TlvUtils.getParseOffset(globalParserMetadata, SHORT_0);
                    nextTlvTag = TlvUtils.parseTlvTag1(apduBuffer, globalParserMetadata, SHORT_0);
                }

                // Protected APDU 'Le'
                short LeTlvOffset = 0, LeTlvLength = 0, Le = 0;
                if (nextTlvTag == TAG_SM_LE) {
                    LeTlvOffset = nextTlvOffset;
                    short LeLength = TlvUtils.parseTlvLength(apduBuffer, globalParserMetadata, SHORT_0);
                    Le = TlvUtils.parseTlvInteger(LeLength, apduBuffer, globalParserMetadata, SHORT_0);
                    LeTlvLength = (short) (TlvUtils.getParseOffset(globalParserMetadata, SHORT_0) - LeTlvOffset);

                    nextTlvTag = TlvUtils.parseTlvTag1(apduBuffer, globalParserMetadata, SHORT_0);
                }

                // CCFB - Cryptographic Checksum Formatted Block
                if (nextTlvTag != TAG_SM_MAC) ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
                short ccfbLength = TlvUtils.parseTlvLength(apduBuffer, globalParserMetadata, SHORT_0);
                short ccfbOffset = TlvUtils.ensureParsableInputAvailable(ccfbLength, globalParserMetadata, SHORT_0);

                if (TlvUtils.getParseLength(globalParserMetadata, SHORT_0) != 0) ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);

                // `Signature.ALG_AES_CMAC_128` is introduced in JavaCard 3.0.5 and is missing from 3.0.4
                // Input = [INS][P1][P2][0x8000000000][TlvEDFB][TlvLe][0x80... <block padding>]
                if (ccfbLength != 16/*signature.getLength()*/ / 2) ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
                // TODO: Secure Messaging MAC
                // signature.update(apduBuffer, apduOffset, (short) 3);
                // signature.update(..., ..., ...); 0x8000000000 padding
                // signature.update(apduBuffer, edfbTlvOffset, edfbTlvLength);
                // signature.update(apduBuffer, LeTlvOffset, LeTlvLength);
                // if (!signature.verify(null, SHORT_0, SHORT_0, apduBuffer, ccfbOffset, ccfbLength)) ISOException.throwIt();

                if (edfbTlvLength > 0) {
                    Lc = cipher.doFinal(apduBuffer, edfbOffset, edfbLength, apduBuffer, LcDataOffset);
                    apduBuffer[LcOffset] = (byte) (Lc & 0xFF);
                    apduInsP1P2LcDataLength = (short) ((LcDataOffset - apduInsOffset) + Lc);
                } else {
                    apduInsP1P2LcDataLength = (short) (apduInsP1P2LcDataLength - 1 - Lc);
                }
                apduBuffer[(short) (apduInsOffset + apduInsP1P2LcDataLength)] = (byte) (Le & 0xFF);
            } catch (CryptoException ex) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            } catch (ISOException ex) {
                if (ex.getReason() == javacard.framework.ISO7816.SW_DATA_INVALID) {
                    ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
                }
                throw ex;
            }
        }
        return apduInsP1P2LcDataLength;
    }

    /**
     * Encrypts response APDU for sending it to the host and returns the length of encrypted data. If doWrap == false,
     * the data will not be encrypted and the length of the original unencrypted data will be returned instead.
     * @param doWrap whether APDU should actually be encrypted
     * @param smCipher secure messaging cipher implementation
     * @param cipherKey secure messaging cipher key
     * @param smMac secure messaging MAC
     * @param signatureKey secure messaging signature key
     * @param INS instruction code of the command APDU received from host
     * @param rapduBuffer byte array buffer containing original unencrypted response APDU. After running the function, it will contain encrypted APDU.
     * @param rapduOffset APDU offset in rapduBuffer
     * @param rapduLength length of response APDU
     * @param statusWord status word
     * @return total length of APDU's INS, P1, P2 and Lc data in apduBuffer
     */
    protected short wrap(boolean doWrap, Cipher smCipher, Key cipherKey, Signature smMac, Key signatureKey, byte INS, byte[] rapduBuffer, short rapduOffset, short rapduLength, short statusWord) {
        if (doWrap) {
            if (!isAuthenticated()) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

            smCipher.init(cipherKey, Cipher.MODE_ENCRYPT);
            // smMac.init(signatureKey, Signature.MODE_SIGN);
            return wrap(doWrap, smCipher, smMac, INS, rapduBuffer, rapduOffset, rapduLength, statusWord);
        }
        return rapduLength;
    }

    /**
     * Encrypts response APDU for sending it to the host and returns the length of encrypted data. If doWrap == false,
     * the data will not be encrypted and the length of the original unencrypted data will be returned instead.
     * @param doWrap whether APDU should actually be encrypted
     * @param cipher secure messaging cipher implementation
     * @param smMac secure messaging signature
     * @param INS instruction code of the command APDU received from host
     * @param rapduBuffer byte array buffer containing original unencrypted response APDU. After running the function, it will contain encrypted APDU.
     * @param rapduOffset APDU offset in rapduBuffer
     * @param rapduLength length of response APDU
     * @param statusWord status word
     * @return total length of APDU's INS, P1, P2 and Lc data in apduBuffer
     */
    protected short wrap(boolean doWrap, Cipher cipher, Signature smMac, byte INS, byte[] rapduBuffer, short rapduOffset, short rapduLength, short statusWord) {
        if (doWrap) {
            if (!isAuthenticated()) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            try {
                try {
                    return wrapStatic(doWrap, cipher, smMac, INS, rapduBuffer, rapduOffset, rapduLength, statusWord);
                } catch (CryptoException ex) {
                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            } catch (ISOException ex) {
                flushAuthentication();
                throw ex;
            }
        }
        return rapduLength;
    }

    /**
     * Encrypts response APDU for sending it to the host and returns the length of encrypted data. If doWrap == false,
     * the data will not be encrypted and the length of the original unencrypted data will be returned instead.
     * @param doWrap whether APDU should actually be encrypted
     * @param cipher secure messaging cipher implementation
     * @param smMac secure messaging signature
     * @param INS instruction code of the command APDU received from host
     * @param rapduBuffer byte array buffer containing original unencrypted response APDU. After running the function, it will contain encrypted APDU.
     * @param rapduOffset APDU offset in rapduBuffer
     * @param rapduLength length of response APDU
     * @param statusWord status word
     * @return total length of APDU's INS, P1, P2 and Lc data in apduBuffer
     */
    public static short wrapStatic(boolean doWrap, Cipher cipher, Signature smMac, byte INS, byte[] rapduBuffer, short rapduOffset, short rapduLength, short statusWord) {
        if (doWrap) {
            if (cipher == null) {
                ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
            }
            try {
                short edfbTlvOffset = rapduOffset, edfbTlvLength = 0, offset = rapduOffset;
                if (rapduLength > 0) {
                    // EDFB - Encrypted Data Formatted Block
                    boolean isOddINS = (INS & 0x01) == 0x01;
                    short padIndicatorByteLength = isOddINS ? SHORT_0 : PAD_INDICATOR_BYTE;
                    short edfbDataSize = (short) ((short) (rapduLength + 16 - 1) / 16 * 16); // TODO: AES block size to constant
                    byte edfbTag = isOddINS ? TAG_SM_DATA_USE_IN_MAC_ODD_INS : TAG_SM_DATA_USE_IN_MAC_EVEN_INS;
                    short edfbDataTLSize = TlvUtils.bytesRequiredForTlvTag1AndLength((short) (padIndicatorByteLength + edfbDataSize));
                    short edfbDataOffset = (short) (rapduOffset + edfbDataTLSize + padIndicatorByteLength);
                    // Use same target offset to so that block wise ciphering would update same block that was read for encrypting
                    edfbTlvLength += edfbDataTLSize + padIndicatorByteLength + cipher.doFinal(rapduBuffer, rapduOffset, rapduLength, rapduBuffer, rapduOffset);
                    // Move encrypted EDFB safely to its correct offset in the same buffer
                    Util.arrayCopyNonAtomic(rapduBuffer, rapduOffset, rapduBuffer, edfbDataOffset, edfbTlvLength);
                    if (!isOddINS) rapduBuffer[(short) (edfbDataOffset - 1)] = PAD_INDICATOR_SM_DATA_EVEN_INS;
                    offset = TlvUtils.writeTlvTag1AndLength(edfbTag, (short) (edfbDataSize + padIndicatorByteLength), rapduBuffer, rapduOffset);
                    offset += padIndicatorByteLength + edfbDataSize;
                }

                // Protected Status Word
                offset = TlvUtils.writeTlvTag1AndLength(TAG_SM_STATUS_WORD, SIZE_OF_SHORT, rapduBuffer, offset);
                offset = Util.setShort(rapduBuffer, offset, statusWord);

                // CCFB - Cryptographic Checksum Formatted Block
                short ccfbInputLength = (short) (offset - rapduOffset);
                // `Signature.ALG_AES_CMAC_128` is introduced in JavaCard 3.0.5 and is missing from 3.0.4
                short signatureLength = (short) (16/*smMac.getLength()*/ / 2); // TODO: Secure Messaging MAC
                offset = TlvUtils.writeTlvTag1AndLength(TAG_SM_MAC, signatureLength, rapduBuffer, offset);

                offset += signatureLength/*smMac.doFinal(rapduBuffer, rapduOffset, ccfbInputLength, rapduBuffer, offset)*/; // TODO: Secure Messaging MAC

                rapduLength = (short) (offset - rapduOffset);
            } catch (CryptoException ex) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            } catch (ISOException ex) {
                if (ex.getReason() == javacard.framework.ISO7816.SW_DATA_INVALID) {
                    ISOException.throwIt(SW_INCORRECT_SECURE_MESSAGING);
                }
                throw ex;
            }
        }
        return rapduLength;
    }

    /**
     * Copies EC curve parameters from ECPrivateKeyService to ECKey.
     * @param ecPrivateKeyService provides EC curve parameters
     * @param ecKey target EC key to copy the curve parameters into
     * @param pointSize EC point size in bytes
     */
    public static void copyDomainParametersFrom(ECPrivateKeyService ecPrivateKeyService, ECKey ecKey, short pointSize) {
        byte[] parameterBuff = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, pointSize);

        short paramLength = ecPrivateKeyService.getECCurveParameter(TAG_EC_CURVE_PRIME, parameterBuff, SHORT_0);
        ecKey.setFieldFP(parameterBuff, SHORT_0, paramLength);
        paramLength = ecPrivateKeyService.getECCurveParameter(TAG_EC_CURVE_COMPONENT_A, parameterBuff, SHORT_0);
        ecKey.setA(parameterBuff, SHORT_0, paramLength);
        paramLength = ecPrivateKeyService.getECCurveParameter(TAG_EC_CURVE_COMPONENT_B, parameterBuff, SHORT_0);
        ecKey.setB(parameterBuff, SHORT_0, paramLength);
        paramLength = ecPrivateKeyService.getECCurveParameter(TAG_EC_CURVE_GENERATOR, parameterBuff, SHORT_0);
        ecKey.setG(parameterBuff, SHORT_0, paramLength);
        paramLength = ecPrivateKeyService.getECCurveParameter(TAG_EC_CURVE_ORDER, parameterBuff, SHORT_0);
        ecKey.setR(parameterBuff, SHORT_0, paramLength);
        if (ecPrivateKeyService.getECCurveParameter(TAG_EC_CURVE_COFACTOR, parameterBuff, SHORT_0) != 2) CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        ecKey.setK(Util.getShort(parameterBuff, SHORT_0));
    }
}
