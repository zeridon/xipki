// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.xipki.security.util.Asn1Util;

/**
 * The PlatformFirmwareSignatureVerification object.
 * <pre>
 * PlatformFirmwareSignatureVerification ::= BIT STRING {
 *     hardwareSRTM (0),
 *     secureBoot   (1)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformFirmwareSignatureVerification extends ASN1Object {

  public static final int hardwareSRTM  = (1 << 7);
  public static final int secureBoot = (1 << 6);

  private ASN1BitString bitString;

  public static PlatformFirmwareSignatureVerification getInstance(Object obj) {
    if (obj instanceof PlatformFirmwareSignatureVerification) {
      return (PlatformFirmwareSignatureVerification)obj;
    } else if (obj != null) {
      return new PlatformFirmwareSignatureVerification(Asn1Util.toASN1BitString(obj));
    }

    return null;
  }

  /**
   * Basic constructor.
   *
   * @param verifications - the bitwise OR of the verification flags.
   */
  public PlatformFirmwareSignatureVerification(int verifications) {
    this.bitString = new DERBitString(verifications);
  }

  private PlatformFirmwareSignatureVerification(ASN1BitString bitString) {
    this.bitString = bitString;
  }

  /**
   * Return true if a given verification bit is set, false otherwise.
   *
   * @param verification combination of verification flags.
   * @return true if all bits are set, false otherwise.
   */
  public boolean hasVerification(int verification) {
    return (bitString.intValue() & verification) == verification;
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
      return "PlatformFirmwareSignatureVerification: 0x" + Integer.toHexString(data[0] & 0xff);
    }

    return "PlatformFirmwareSignatureVerification: 0x" +
        Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
  }

  public ASN1Primitive toASN1Primitive() {
    return bitString;
  }

}
