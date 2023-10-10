# ARMIS Manager Applet

The manager applet of the ARMIS applet ecosystem.

## Building the applet

```bash
ant {target-name}
```

Available targets:
* `init` - create the `dist` directory
* `clean` - delete the `dist` directory and its contents
* `build` - create the `dist` directory (if not yet present) and build the applet's CAP and EXP files using [`ant-javacard`](https://github.com/martinpaljak/ant-javacard); **NB:** requires `util-lib` to be already built!

## Applet APDU interface

### GP, INSTALL (for personalization) STORE DATA

| Command parameter | Value                   | Notes                                                                 |
| ----------------- | ----------------------- | --------------------------------------------------------------------- |
| CLA               | `0x80`                  | ISO class                                                             |
| INS               | `0xE2`                  | STORE DATA instruction                                                |
| P1                | 0x**b8**000000**b1**    | b8 indicates if the command is last in the sequence. b1 indicates if response is expected. |
| P2                | Sequence counter        | Sequence counter of commands starting from 0                          |
| Lc                | *Nc*                    | The number of following command data bytes                            |
| Data field        | Nested command          | Nested APDU to invoke specific methods thorough STORE DATA            |

> **Remark!** Extended APDU cannot be used with STORE DATA command.

#### Nested command

Nested command is a way to wrap procedural instruction into the STORE DATA command. The same rules apply as for the
standard APDU. The only difference is that there is no CLA which is not needed.

| Command parameter | Length                   | Notes                                                                 |
| ----------------- | ------------------------ | --------------------------------------------------------------------- |
| INS               | 1                        | Instruction                                                           |
| P1                | 1                        | Instruction parameter 1                                               |
| P2                | 1                        | Instruction parameter 2                                               |
| Lc                | 1                        | Number of bytes present in the data field of the command              |
| Data field        | variable=Lc              | Array of bytes sent in the data field of the command                  |
| Le                | 1                        | Maximum number of bytes expected in the data field of the response to the command |

| Response parameter | Value    | Notes                         |
| ------------------ | -------- | ----------------------------- |
| SW1-SW2            | `0x6984` | Invalid nested APDU structure |
|                    | `0x6D00` | Nested INS not supported      |

#### Nested command: PUT DATA (0xDB), case 3s APDU

The PUT DATA command is used for storing one primitive data object or one or more data objects contained in a constructed
data object within the applet context. The exact storing functions (writing once and/or updating and/or appending) are
to be induced by the definition, or the nature of the data objects. Additionally, there is a use case where only INS may
need to be provided. 

Used to:
* Create a new EC private key with the specified size and EC curve parameters
* Generate a valid EC key-pair based on the specified size and EC curve parameters
* Return the encoded EC curve point of the generated public key

| Command parameter | Value                   | Notes                                                            |
| ----------------- | ----------------------- | ---------------------------------------------------------------- |
| INS               | `0xDB`                  | PUT DATA instruction                                             |
| P1-P2             | *Data identifier tag*   | Data identifier tag. Possible values: `0x7F21` and `0x7F49`      |
| Lc                | *Tag specific length*   | Inspect the data identifier tag structure                        |
| Data field        | *Tag specific TLV data* | Inspect the data identifier tag structure                        |

| Response parameter | Value                                        | Notes                     |
| ------------------ | -------------------------------------------- | --------------------------|
| SW1-SW2            | `0x6D00`                                     | Nested P1P2 not supported |

**TLV encoding of the EC curve parameters:**

| TLV tag                           | Expected length                | Description                                          |
| --------------------------------: | ------------------------------ | ---------------------------------------------------- |
| `0x7F49` &nbsp;&nbsp;&nbsp;&nbsp; | -                              | A TLV sequence containing all the following elements (*in any order*) |
|        `0x81`                     | `(key-size + 7) / 8`           | Prime field                                          |
|        `0x82`                     | `(key-size + 7) / 8`           | Coefficient A                                        |
|        `0x83`                     | `(key-size + 7) / 8`           | Coefficient B                                        |
|        `0x84`                     | `1 + 2 * ((key-size + 7) / 8)` | Generator (a.k.a the fixed base point) G             |
|        `0x85`                     | `(key-size + 7) / 8`           | Order of the fixed point G                           |
|        `0x87`                     | `1` or `2`                     | Cofactor                                             |

The value *key-size* refers to the EC key size in bits.
The expression `(key-size + 7) / 8` refers to the EC key size in bytes.
The expression `1 + 2 * ((key-size + 7) / 8)` refers to the EC curve point size in plain text format.

| Response parameter | Value                                        | Notes                                      |
| ------------------ | -------------------------------------------- | ------------------------------------------ |
| Data field         | -                                            | Absent                                     |
| SW1-SW2            | `0x9000`                                     | Successful operation                       |
|                    | `0x6981`                                     | Requested algorithm associated with the specified type, size of key and key encryption interface is not supported |
|                    | `0x6984`                                     | - Invalid TLV structure                    |
|                    |                                              | - Invalid curve component value            |
|                    | `0x6987`                                     | - Invalid curve component length           |
|                    |                                              | - Transient keys not initialized           |
|                    | `0x6A80`                                     | Unknown curve component tag provided       |

**TLV encoding of the certificate file chunks:**

| TLV tag                           | Type         | Description                                                 |
| --------------------------------: | ------------ | ----------------------------------------------------------- |
| `0x7F21` &nbsp;&nbsp;&nbsp;&nbsp; | SEQUENCE     | A TLV sequence containing all the following elements (*in the following order*) |
|        `0x02`                     | INTEGER      | Offset into the certificate file                            |
|        `0x04`                     | OCTET STRING | Chunk of the certificate to write into the certificate file |

**NB:** Prior to invoking this command, the applet's key-pair must already been generated, otherwise this command will fail!<br>
**NB:** The size of the certificate file is determined from the first few bytes of the certificate data, so the first chunk of the certificate to be sent into the applet must be from offset `0` and long enough to be able to contain the certificate's first SEQUENCE tag and the following TLV length (up to 4 bytes in total).<br>
**NB:** Sending the final chunk of the certificate (`offset + chunk-length = certificate-file-size`) into the applet, triggers the applet's transition into the **personalized** state.

| Response parameter | Value                 | Notes                                            |
| ------------------ | --------------------- | ------------------------------------------------ |
| Data field         | -                     | Absent                                           |
| SW1-SW2            | `0x9000`              | Successful operation                             |
|                    | `0x6985`              | State prohibits certificate writing              |
|                    | `0x6984`              | - Invalid TLV structure                          |
|                    |                       | - Negative destination offset                    |
|                    |                       | - First chunk data doesn't begin with `0x30` tag |
|                    |                       | - Invalid new certificate size. MIN:1 MAX:2048   |
|                    |                       | - Certificate file size not set                  |
|                    |                       | - Destination offset is greater than file length |

#### Nested command: GET DATA (0xCB), case 4s APDU

| Command parameter | Value                   | Notes                                                            |
| ----------------- | ----------------------- | ---------------------------------------------------------------- |
| INS               | `0xCB`                  | GET DATA instruction                                             |
| P1-P2             | *Data identifier tag*   | Data identifier tag. Possible values: `0x7F21`                   |
| Lc                | *Tag specific length*   | Inspect the data identifier tag structure                        |
| Data field        | *Tag specific TLV data* | Inspect the data identifier tag structure                        |
| Le                | *Read-length*           | Maximum number of bytes to read. Le value needs special handling: 256 is encoded as `0x00`. Le byte is required (this nested APDU is expected to be case 4s), therefore 0 read-length is not supported and at least 1 byte is expected to be read. |

| Response parameter | Value                                        | Notes                               |
| ------------------ | -------------------------------------------- | ----------------------------------- |
| SW1-SW2            | `0x6F00`                                     | Available output buffer length is 0 |
|                    | `0x6D00`                                     | Nested P1P2 not supported           |

GET DATA may return less data than the requested `Le` value.

**TLV encoding of the certificate file chunks:**

| TLV tag                           | Type         | Description                                                 |
| --------------------------------- | ------------ | ----------------------------------------------------------- |
| `0x7F21` &nbsp;&nbsp;&nbsp;&nbsp; | SEQUENCE     | A TLV sequence containing all the following elements (*in the following order*) |
|        `0x02`                     | INTEGER      | Offset into the file where to start reading from            |

| Response parameter | Value                 | Notes                                            |
| ------------------ | --------------------- | ------------------------------------------------ |
| Data field         | *Data*                |                                                  |
| SW1-SW2            | `0x9000`              | Successful operation                             |
|                    | `0x6A82`              | Certificate not found                            |
|                    | `0x6984`              | - Invalid TLV structure                          |
|                    |                       | - Negative destination offset                    |
|                    |                       | - Destination offset is greater than file length |

#### Nested command: GENERATE ASYMMETRIC KEYPAIR (0x47), like case 1 APDU but only INS is required

This command initiates the generation and storing of an asymmetric key pair and returns the public key of an asymmetric
key pair previously generated in the card or imported. 

Used to:
* Create a new EC private key with the specified size and EC curve parameters
* Generate a valid EC key-pair based on the specified size and EC curve parameters
* Return the encoded EC curve point of the generated public key

| Command parameter | Value                   | Notes                                                            |
| ----------------- | ----------------------- | ---------------------------------------------------------------- |
| INS               | `0x47`                  | Generate key-pair instruction                                    |

| Response parameter | Value                                        | Notes                                      |
| ------------------ | -------------------------------------------- | ------------------------------------------ |
| Data field         | 0x04 &#124; x &#124; y                       | Generated public key                       |
| SW1-SW2            | `0x9000`                                     | Successfully generated public key          |
|                    | `0x6985`                                     | - input parameter key objects are mismatched - different algorithms or different key sizes |
|                    |                                              | - algorithm associated with the specified type, size of key is not supported |
|                    |                                              | - pre-initialized Field, A, B, G and R parameter set in public EC key is invalid |
|                    |                                              | - some EC key curve components are uninitialized |
