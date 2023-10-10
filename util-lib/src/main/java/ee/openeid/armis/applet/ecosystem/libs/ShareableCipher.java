package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.Shareable;

public interface ShareableCipher extends Shareable {
    byte getCipherAlgorithm();
    byte getPaddingAlgorithm();
    short update(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);
    short doFinal(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);
    void dispose();
}
