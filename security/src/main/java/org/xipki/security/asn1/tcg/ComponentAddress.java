// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.security.OIDs;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * ComponentAddress ::= SEQUENCE {
 *     addressType  AddressType,
 *     addressValue UTF8String (SIZE (1..STRMAX))
 * }
 * AddressType ::= OBJECT IDENTIFIER ( tcg-address-ethernetmac | tcg-address-wlanmac
 *                 | tcg-address-bluetoothmac )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentAddress extends ASN1Object {

  private final ASN1ObjectIdentifier addressType;

  private final String addressValue;

  public ComponentAddress(ASN1ObjectIdentifier addressType, String addressValue) {
    this.addressType = Args.notNull(addressType, "addressType");
    this.addressValue = Args.lengthRange(addressValue, "addressValue", 1, TcgConstants.STRMAX);

    if (!(OIDs.TCG.tcg_address_ethernetmac.equals(addressType) ||
        OIDs.TCG.tcg_address_wlanmac.equals(addressType) ||
        OIDs.TCG.tcg_address_bluetoothmac.equals(addressType))) {
      throw new IllegalArgumentException("invalid addressType " + addressType.getId());
    }
  }

  public String addressValue() {
    return addressValue;
  }

  public ASN1ObjectIdentifier addressType() {
    return addressType;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[] {addressType, new DERUTF8String(addressValue)});
  }

  public static ComponentAddress getInstance(Object  obj) {
    if (obj instanceof ComponentAddress) {
      return (ComponentAddress) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      String value = Asn1Util.getUTF8String(seq.getObjectAt(1));
      return new ComponentAddress(type, value);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
