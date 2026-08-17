// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.xipki.security.util.Asn1Util;

/**
 * The PlatformFirmwareCapabilities object.
 * <pre>
 * PlatformFirmwareCapabilities ::= BIT STRING {
 *     fwSetupAuthLocal (0),
 *     fwSetupAuthRemote (1),
 *     sMMProtection (2),
 *     fwKernelDMAProtection (3)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformFirmwareCapabilities extends ASN1Object {

  public static final int fwSetupAuthLocal  = (1 << 7);
  public static final int fwSetupAuthRemote = (1 << 6);
  public static final int sMMProtection     = (1 << 5);
  public static final int fwKernelDMAProtection = (1 << 4);

  private ASN1BitString bitString;

  public static PlatformFirmwareCapabilities getInstance(Object obj) {
    if (obj instanceof PlatformFirmwareCapabilities) {
      return (PlatformFirmwareCapabilities)obj;
    } else if (obj != null) {
      return new PlatformFirmwareCapabilities(Asn1Util.toASN1BitString(obj));
    }

    return null;
  }

  /**
   * Basic constructor.
   *
   * @param usage - the bitwise OR of the capability flags.
   */
  public PlatformFirmwareCapabilities(int usage) {
    this.bitString = new DERBitString(usage);
  }

  private PlatformFirmwareCapabilities(ASN1BitString bitString) {
    this.bitString = bitString;
  }

  /**
   * Return true if a given capability bit is set, false otherwise.
   *
   * @param capabilities combination of capability flags.
   * @return true if all bits are set, false otherwise.
   */
  public boolean hasCapabilities(int capabilities) {
    return (bitString.intValue() & capabilities) == capabilities;
  }

  public byte[] getBytes() {
    return bitString.getBytes();
  }

  public int getPadBits() {
    return bitString.getPadBits();
  }

  public String toString() {
    byte[] data = bitString.getBytes();
    if (data.length == 1) {
      return "PlatformFirmwareCapabilities: 0x" + Integer.toHexString(data[0] & 0xff);
    }

    return "PlatformFirmwareCapabilities: 0x" +
        Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
  }

  public ASN1Primitive toASN1Primitive() {
    return bitString;
  }

}
