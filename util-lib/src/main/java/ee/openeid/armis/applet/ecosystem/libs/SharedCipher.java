package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.JCSystem;
import javacardx.crypto.Cipher;

public class SharedCipher implements ShareableCipher {

    private Cipher cipher;
    /**
     * Cipher class in Java Card API version 3.0.4 does not expose {@code getCipherAlgorithm()} method, so this
     * information must be provided manually to enable cipher algorithm to be queryable.
     */
    private byte cipherAlgorithm;
    /**
     * Cipher class in Java Card API version 3.0.4 does not expose {@code getPaddingAlgorithm()} method, so this
     * information must be provided manually to enable padding algorithm to be queryable.
     */
    private byte paddingAlgorithm;

    SharedCipher(Cipher cipher, byte cipherAlgorithm, byte paddingAlgorithm) {
        this.cipher = cipher;
        this.cipherAlgorithm = cipherAlgorithm;
        this.paddingAlgorithm = paddingAlgorithm;
    }

    @Override
    public byte getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    @Override
    public byte getPaddingAlgorithm() {
        return paddingAlgorithm;
    }

    @Override
    public short update(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        return cipher.update(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    @Override
    public short doFinal(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    @Override
    public void dispose() {
        cipher = null;
        JCSystem.requestObjectDeletion();
    }

}
