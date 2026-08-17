// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.xipki.util.codec.Args;

import java.util.HashMap;

/**
 * The AttributeStatus enumeration.
 * <pre>
 * AttributeStatus ::= ENUMERATED {
 *     added    (0),
 *     modified (1),
 *     removed  (2)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeStatus extends ASN1Object {

  private static final HashMap<Integer, AttributeStatus> map = new HashMap<>();

  public static final AttributeStatus added = f(0);
  public static final AttributeStatus modified = f(1);
  public static final AttributeStatus removed = f(2);

  private final int value;

  private final String text;

  private static AttributeStatus f(int value) {
    AttributeStatus asn1 = new AttributeStatus(value);
    map.put(value, asn1);
    return asn1;
  }

  public static AttributeStatus getInstance(Object o) {
    Args.notNull(o, "o");
    if (o instanceof AttributeStatus) {
      return (AttributeStatus)o;
    } else {
      return lookup(ASN1Enumerated.getInstance(o).intValueExact());
    }
  }

  private AttributeStatus(int value) {
    this.value = Args.range(value, "value", 0, 2);
    switch (value) {
      case 0:
        this.text = "added";
        break;
      case 1:
        this.text = "modified";
        break;
      default:
        this.text = "removed";
    }
  }

  @Override
  public String toString() {
    return  "AttributeStatus: " + text;
  }

  public int getValue() {
      return value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new ASN1Enumerated(value);
  }

  public static AttributeStatus lookup(int value) {
    AttributeStatus ret = map.get(value);
    if (ret == null){
      throw new IllegalArgumentException("invalid AttributeStatus " + value);
    }
    return ret;
  }
}
