# Example ARMIS Client Applet

An example third party applet that can be used to try out third party applet remote installation and personalization.

## Building the library

### Prerequisites
* Java 1.8 JDK
* Apache Ant

### Build

```bash
ant {target-name}
```

Available targets:
* `init` - create the `dist` directory
* `clean` - delete the `dist` directory and its contents
* `build` - create the `dist` directory (if not yet present) and build the library's CAP and EXP files using [`ant-javacard`](https://github.com/martinpaljak/ant-javacard)
