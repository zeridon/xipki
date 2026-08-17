// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.xipki.security.util.Asn1Util;

/**
 * The RTMTypes object.
 * <pre>
 * RTMTypes ::= BIT STRING {
 *     static         (0),
 *     dynamic        (1),
 *     nonHost        (2),
 *     virtual        (3),
 *     hardwareStatic (4),
 *     bMC            (5)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class RTMTypes extends ASN1Object {

  public static final int _static  = (1 << 7);
  public static final int dynamic = (1 << 6);
  public static final int nonHost     = (1 << 5);
  public static final int virtual = (1 << 4);
  public static final int hardwareStatic = (1 << 3);
  public static final int bMC = (1 << 2);

  private ASN1BitString bitString;

  public static RTMTypes getInstance(Object obj) {
    if (obj instanceof RTMTypes) {
      return (RTMTypes)obj;
    } else if (obj != null) {
      return new RTMTypes(Asn1Util.toASN1BitString(obj));
    }

    return null;
  }

  /**
   * Basic constructor.
   *
   * @param types - the bitwise OR of the type flags.
   */
  public RTMTypes(int types) {
    this.bitString = new DERBitString(types);
  }

  private RTMTypes(ASN1BitString bitString) {
    this.bitString = bitString;
  }

  /**
   * Return true if a given type bit is set, false otherwise.
   *
   * @param types combination of type flags.
   * @return true if all bits are set, false otherwise.
   */
  public boolean hasCapabilities(int types) {
    return (bitString.intValue() & types) == types;
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
      return "RTMTypes: 0x" + Integer.toHexString(data[0] & 0xff);
    }

    return "RTMTypes: 0x" + Integer.toHexString((data[1] & 0xff) << 8 | (data[0] & 0xff));
  }

  public ASN1Primitive toASN1Primitive() {
    return bitString;
  }

}
