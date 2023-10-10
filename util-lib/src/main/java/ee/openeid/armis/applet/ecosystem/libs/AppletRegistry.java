package ee.openeid.armis.applet.ecosystem.libs;

import javacard.framework.Shareable;

public interface AppletRegistry extends Shareable {
    boolean isRegistered();
    void registerApplet();
    void unregisterApplet();
}
