package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.BYTE_0;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SHORT_0;

// TODO: turn all ConcatKDF logic into a static method instead of an instantiable object
public class ConcatKDF {

    private final static short INT_BYTES_COUNT = 4;

    private final MessageDigest messageDigest;
    private byte[] z;
    private short zOffset;
    private short zLength;
    private byte[] otherInfo;
    private short otherInfoOffset;
    private short otherInfoLength;

    public ConcatKDF(MessageDigest messageDigest) throws CryptoException {
        this.messageDigest = messageDigest;
    }

    public void init(
            byte[] z, short zOffset, short zLength,
            byte[] otherInfo, short otherInfoOffset, short otherInfoLength)
            throws CryptoException {
        ensureInitStatus(z, zOffset, zLength, otherInfo, otherInfoOffset, otherInfoLength);
        this.z = z;
        this.zOffset = zOffset;
        this.zLength = zLength;
        this.otherInfo = otherInfo;
        this.otherInfoOffset = otherInfoOffset;
        this.otherInfoLength = otherInfoLength;
    }

    private static void ensureInitStatus(byte[] z, short zOffset, short zLength, byte[] otherInfo, short otherInfoOffset, short otherInfoLength) {
        if (z == null ||
            zOffset < 0 ||
            zLength <= 0 ||
            otherInfoOffset < 0 ||
            otherInfoLength < 0 ||
            (otherInfoLength > 0 && otherInfo == null)) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
    }

    public short generate(byte[] outBuff, short outOffset, short outLength) throws CryptoException {
        ensureInitStatus(z, zOffset, zLength, otherInfo, otherInfoOffset, otherInfoLength);
        // Step 1 - the derivation result must be more than 1 byte
        if (outLength <= 0) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        // Step 2 redundant for JavaCard. (2^32 - 1) is more than Short.MAX_VALUE
        // Step 3 - Init counter as 0x00000000
        byte[] workBuffer = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) (INT_BYTES_COUNT + messageDigest.getLength()));
        Util.arrayFillNonAtomic(workBuffer, SHORT_0, INT_BYTES_COUNT, BYTE_0);
        // (skip) Step 4 - counter || Z || OtherInfo should not be greater than digest output
        // if (counter.length + zLength + otherInfoLength > messageDigest.getLength()) {
        //     CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        // }
        // Step 5 - Clearing the result (outBuff) array is redundant
        // Step 6 - Compute result
        do {
            // Step 6.1 - Increment counter by 1
            for (byte i = (byte) (INT_BYTES_COUNT - 1); i >= 0; i--) if (++workBuffer[i] != 0) break;
            // Step 6.2 - Compute K(i) = H(counter || Z || OtherInfo)
            messageDigest.update(workBuffer, SHORT_0, INT_BYTES_COUNT);
            messageDigest.update(z, zOffset, zLength);
            if (otherInfoLength > 0) messageDigest.update(otherInfo, otherInfoOffset, otherInfoLength);
            // Use workBuffer as dummy input with 0 length to avoid NullPointerException
            short bytesToCopy = messageDigest.doFinal(workBuffer, SHORT_0, SHORT_0, workBuffer, INT_BYTES_COUNT);
            // Step 6.3 - Set Result(i) = Result(i – 1) || K(i).
            // and Step 7 - Set DerivedKeyingMaterial equal to the leftmost L bits of Result(n).
            bytesToCopy = bytesToCopy > outLength ? outLength : bytesToCopy;
            outOffset = Util.arrayCopyNonAtomic(workBuffer, INT_BYTES_COUNT, outBuff, outOffset, bytesToCopy);
            outLength -= bytesToCopy;
        } while (outLength > 0);
        clean();
        // Step 8 - Output DerivedKeyingMaterial
        return outOffset;
    }

    private void clean() {
        this.z = null;
        this.zOffset = 0;
        this.zLength = 0;
        this.otherInfo = null;
        this.otherInfoOffset = 0;
        this.otherInfoLength = 0;
    }

}
