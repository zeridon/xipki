// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.xipki.security.util.Asn1Util;

/**
 * The PlatformFirmwareUpdateCompliance object.
 * <pre>
 * PlatformFirmwareUpdateCompliance ::= BIT STRING {
 *     sp800-147  (0),
 *     sp800-147B (1),
 *     sp800-193  (2),
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformFirmwareUpdateCompliance extends ASN1Object {

  public static final int sp800_147  = (1 << 7);
  public static final int sp800_147B = (1 << 6);
  public static final int sp800_193  = (1 << 5);

  private ASN1BitString bitString;

  public static PlatformFirmwareUpdateCompliance getInstance(Object obj) {
    if (obj instanceof PlatformFirmwareUpdateCompliance) {
      return (PlatformFirmwareUpdateCompliance)obj;
    } else if (obj != null) {
      return new PlatformFirmwareUpdateCompliance(Asn1Util.toASN1BitString(obj));
    }

    return null;
  }

  /**
   * Basic constructor.
   *
   * @param compliance - the bitwise OR of the compliance flags.
   */
  public PlatformFirmwareUpdateCompliance(int compliance) {
    this.bitString = new DERBitString(compliance);
  }

  private PlatformFirmwareUpdateCompliance(ASN1BitString bitString) {
    this.bitString = bitString;
  }

  /**
   * Return true if a given compliance bit is set, false otherwise.
   *
   * @param compliance combination of compliance flags.
   * @return true if all bits are set, false otherwise.
   */
  public boolean hasCompliance(int compliance) {
    return (bitString.intValue() & compliance) == compliance;
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
      return "PlatformFirmwareUpdateCompliance: 0x" + Integer.toHexString(data[0] & 0xff);
    }

    return "PlatformFirmwareUpdateCompliance: 0x" +
        Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
  }

  public ASN1Primitive toASN1Primitive() {
    return bitString;
  }

}
