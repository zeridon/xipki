// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;

/**
 * The PlatformHardwareCapabilities object.
 * <pre>
 * PlatformHardwareCapabilities ::= BIT STRING {
 *     iOMMUSupport                (0),
 *     trustedExecutionEnvironment (1),
 *     physicalTamperProtection    (2),
 *     physicalTamperDetection     (3),
 *     firmwareFlashWP             (4),
 *     externalDMASupport          (5)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformHardwareCapabilities extends ASN1Object {

  public static final int iOMMUSupport  = (1 << 7);
  public static final int trustedExecutionEnvironment = (1 << 6);
  public static final int physicalTamperProtection     = (1 << 5);
  public static final int physicalTamperDetection = (1 << 4);
  public static final int firmwareFlashWP = (1 << 3);
  public static final int externalDMASupport = (1 << 2);

  private ASN1BitString bitString;

  public static PlatformHardwareCapabilities getInstance(Object obj) {
    if (obj instanceof PlatformHardwareCapabilities) {
      return (PlatformHardwareCapabilities)obj;
    } else if (obj != null) {
      return new PlatformHardwareCapabilities(ASN1BitString.getInstance(obj));
    }

    return null;
  }

  /**
   * Basic constructor.
   *
   * @param usage - the bitwise OR of the capability flags.
   */
  public PlatformHardwareCapabilities(int usage) {
    this.bitString = new DERBitString(usage);
  }

  private PlatformHardwareCapabilities(ASN1BitString bitString) {
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
      return "PlatformHardwareCapabilities: 0x" + Integer.toHexString(data[0] & 0xff);
    }

    return "PlatformHardwareCapabilities: 0x" +
        Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
  }

  public ASN1Primitive toASN1Primitive() {
    return bitString;
  }

}
