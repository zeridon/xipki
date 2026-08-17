// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.xipki.util.codec.Args;

import java.util.HashMap;

/**
 * The StrengthOfFunction enumeration.
 * <pre>
 * StrengthOfFunction ::= ENUMERATED {
 *     basic  (0),
 *     medium (1),
 *     high   (2)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class StrengthOfFunction extends ASN1Object {

  private static final HashMap<Integer, StrengthOfFunction> map = new HashMap<>();

  public static final StrengthOfFunction basic = f(0);
  public static final StrengthOfFunction medium = f(1);
  public static final StrengthOfFunction high = f(2);

  private final int value;

  private final String text;

  private static StrengthOfFunction f(int value) {
    StrengthOfFunction asn1 = new StrengthOfFunction(value);
    map.put(value, asn1);
    return asn1;
  }

  public static StrengthOfFunction getInstance(Object o) {
    Args.notNull(o, "o");
    if (o instanceof StrengthOfFunction) {
      return (StrengthOfFunction)o;
    } else {
      return lookup(ASN1Enumerated.getInstance(o).intValueExact());
    }
  }

  private StrengthOfFunction(int value) {
    this.value = Args.range(value, "value", 0, 2);
    switch (value) {
      case 0:
        this.text = "basic";
        break;
      case 1:
        this.text = "medium";
        break;
      default:
        this.text = "high";
    }
  }

  @Override
  public String toString() {
    return  "StrengthOfFunction: " + text;
  }

  public int getValue() {
      return value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new ASN1Enumerated(value);
  }

  public static StrengthOfFunction lookup(int value) {
    StrengthOfFunction ret = map.get(value);
    if (ret == null){
      throw new IllegalArgumentException("invalid StrengthOfFunction " + value);
    }
    return ret;
  }
}
