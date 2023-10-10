package ee.openeid.armis.applet.ecosystem;

import ee.openeid.armis.applet.ecosystem.libs.ECDHE;
import ee.openeid.armis.applet.ecosystem.libs.ShareableCipher;
import javacard.framework.CardRuntimeException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SharedECDHE implements ECDHE {

    private byte[] sharedSecret;
    private byte[] signedEphemeralPublicKey;

    private final short signedEphemeralPublicKeyOffset;
    private final short signedEphemeralPublicKeyLength;

    SharedECDHE(byte[] sharedSecret, byte[] signedEphemeralPublicKey, short offset, short length) {
        this.sharedSecret = sharedSecret;
        this.signedEphemeralPublicKey = signedEphemeralPublicKey;
        this.signedEphemeralPublicKeyOffset = offset;
        this.signedEphemeralPublicKeyLength = length;
    }

    @Override
    public ShareableCipher forAesCrypto(byte cipherAlgorithm, byte paddingAlgorithm, byte secretMode, byte[] publicData, short publicOffset, short publicLength) {
        CardRuntimeException.throwIt((short) 0); // TODO: not implemented yet
        return null;
    }

    @Override
    public short getSecret(byte[] bTargetArray, short bTargetOffset) {
        // Create a local handle to the shared secret buffer
        byte[] bSourceArray = sharedSecret;
        // Get the length of the source array
        short bSourceLength = (short) bSourceArray.length;
        boolean skipReturning = bTargetArray == null && bTargetOffset == 0;
        if (!skipReturning) {
            // Copy the contents of the source array into the specified target array starting from the specified position, non-atomically
            Util.arrayCopyNonAtomic(bSourceArray, (short) 0, bTargetArray, bTargetOffset, bSourceLength);
        }
        // Return the length of the source array
        return bSourceLength;
    }

    @Override
    public short getSignedEphemeralPublicKey(byte[] bTargetArray, short bTargetOffset) {
        // Create a local variable for holding the length value
        short bSourceLength = signedEphemeralPublicKeyLength;
        // Copy the contents of the source array into the specified target array starting from the specified position, non-atomically
        Util.arrayCopyNonAtomic(signedEphemeralPublicKey, signedEphemeralPublicKeyOffset, bTargetArray, bTargetOffset, bSourceLength);
        // Return the length of the ephemeral public key + signature
        return bSourceLength;
    }

    @Override
    public void dispose() {
        sharedSecret = null;
        signedEphemeralPublicKey = null;
        JCSystem.requestObjectDeletion();
    }

}
