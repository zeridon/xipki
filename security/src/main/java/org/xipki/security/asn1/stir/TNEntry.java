// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * RFC8226
 * <pre>
 * TNEntry ::= CHOICE {
 *    spc    [0] ServiceProviderCode,
 *    range  [1] TelephoneNumberRange,
 *    one    [2] TelephoneNumber
 * }
 *
 * ServiceProviderCode ::= IA5String
 *
 *  -- SPCs may be OCNs, various SPIDs, or other SP identifiers
 *  -- from the telephone network.
 *
 *  TelephoneNumberRange ::= SEQUENCE {
 *     start TelephoneNumber,
 *     count INTEGER (2..MAX),
 *     ...
 *  }
 *
 *  TelephoneNumber ::= IA5String (SIZE (1..15)) (FROM ("0123456789#*"))
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TNEntry extends ASN1Object {

  private final DERIA5String spc;

  private final TelephoneNumberRange range;

  private final DERIA5String one;

  private TNEntry(String spc, TelephoneNumberRange range, String one) {
    if (spc != null) {
      this.spc = new DERIA5String(spc);
    } else {
      this.spc = null;
    }

    this.range = range;

    if (one != null) {
      this.one = new DERIA5String(assertValidTelephoneNumber(one, "one"));
    } else {
      this.one = null;
    }
  }

  static String assertValidTelephoneNumber(String str, String name) {
    Args.range(str.length(), name, 1, 15);
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (!((c >= '0' && c <= '9') || c == '#' || c == '*')) {
        throw new IllegalArgumentException("invalid char in " + name + ": '" + c + "'");
      }
    }
    return str;
  }

  public static TNEntry ofSpc(String spc) {
    return new TNEntry(Args.notNull(spc, "spc"), null, null);
  }

  public static TNEntry ofRange(TelephoneNumberRange range) {
    return new TNEntry(null, Args.notNull(range, "range"), null);
  }

  public static TNEntry ofOne(String one) {
    return new TNEntry(null, null, Args.notNull(one, "one"));
  }

  public DERIA5String getSpc() {
    return spc;
  }

  public TelephoneNumberRange getRange() {
    return range;
  }

  public DERIA5String getOne() {
    return one;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    if (spc != null) {
      return new DERTaggedObject(true, 0, spc);
    } else if (range != null) {
      return new DERTaggedObject(true, 1, range);
    } else {
      return new DERTaggedObject(true, 2, one);
    }
  }

  public static TNEntry getInstance(Object  obj) {
    if (obj instanceof TNEntry) {
      return (TNEntry) obj;
    } else if (obj instanceof ASN1TaggedObject) {
      ASN1TaggedObject tObj = (ASN1TaggedObject) obj;
      int tag = tObj.getTagNo();
      ASN1Encodable tBase = Asn1Util.getBaseObject(tObj);
      if (tag == 0) {
        return ofSpc(Asn1Util.getIA5String(tBase));
      } else if (tag == 1) {
        return ofRange((TelephoneNumberRange.getInstance(tBase)));
      } else if (tag == 2) {
        return ofOne(Asn1Util.getIA5String(tBase));
      } else {
        throw new IllegalArgumentException("invalid tag " + tag);
      }
    } else {
      throw new IllegalArgumentException("invalid object " + obj);
    }
  }

}
