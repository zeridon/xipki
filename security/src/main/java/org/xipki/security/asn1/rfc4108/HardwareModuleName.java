// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.rfc4108;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

/**
 *  The hardware module name form is identified by the id-on-
 *  hardwareModuleName object identifier:
 *
 *  <pre>
 *     id-on-hardwareModuleName OBJECT IDENTIFIER ::= {
 *       iso(1) identified-organization(3) dod(6) internet(1) security(5)
 *       mechanisms(5) pkix(7) on(8) 4 }
 *  </pre>
 *
 *  A HardwareModuleName is composed of an object identifier and an octet
 *  string:
 *
 *  <pre>
 *     HardwareModuleName ::= SEQUENCE {
 *       hwType OBJECT IDENTIFIER,
 *       hwSerialNum OCTET STRING }
 * </pre>
 *
 *  The fields of the HardwareModuleName type have the following
 *  meanings:
 * <ol>
 * <li>hwType is an object identifier that identifies the type of hardware
 *     module.  A unique object identifier names a hardware model and
 *     revision.</li>
 * <li>hwSerialNum is the serial number of the hardware module.  No
 *     particular structure is imposed on the serial number; it need not
 *     be an integer.  However, the combination of the hwType and
 *     hwSerialNum uniquely identifies the hardware module.</li>
 * </ol>
 *
 * @author Lijun Liao (xipki)
 */
public class HardwareModuleName extends ASN1Object {

  private final ASN1ObjectIdentifier hwType;

  private final byte[] hwSerialNum;

  public HardwareModuleName(ASN1ObjectIdentifier hwType, byte[] hwSerialNum) {
    this.hwType = Args.notNull(hwType, "hwType");
    this.hwSerialNum = Args.notEmptyBytes(hwSerialNum, "hwSerialNum");
  }

  public ASN1ObjectIdentifier hwType() {
    return hwType;
  }

  public byte[] hwSerialNum() {
    return hwSerialNum;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[]{ hwType, new DEROctetString(hwSerialNum) });
  }

  public static HardwareModuleName getInstance(Object obj) {
    if (obj instanceof HardwareModuleName) {
      return (HardwareModuleName) obj;
    } else {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int size = seq.size();
      if (size != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }
      return new HardwareModuleName(
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)),
          ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    }
  }

}
