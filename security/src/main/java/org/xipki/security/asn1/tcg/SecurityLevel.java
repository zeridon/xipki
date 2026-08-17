// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.xipki.util.codec.Args;

import java.util.HashMap;

/**
 * The EvaluationAssuranceLevel enumeration.
 * <pre>
 * SecurityLevel ::= ENUMERATED {
 *     level1 (1),
 *     level2 (2),
 *     level3 (3),
 *     level4 (4)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SecurityLevel extends ASN1Object {

  private static final HashMap<Integer, SecurityLevel> map = new HashMap<>();

  public static final SecurityLevel level1 = f(1);
  public static final SecurityLevel level2 = f(2);
  public static final SecurityLevel level3 = f(3);
  public static final SecurityLevel level4 = f(4);

  private final int value;

  private final String text;

  private static SecurityLevel f(int value) {
    SecurityLevel asn1 = new SecurityLevel(value);
    map.put(value, asn1);
    return asn1;
  }

  public static SecurityLevel getInstance(Object o) {
    if (o instanceof SecurityLevel) {
      return (SecurityLevel)o;
    } else if (o != null) {
      return lookup(ASN1Enumerated.getInstance(o).intValueExact());
    }

    return null;
  }

  private SecurityLevel(int value) {
    this.value = Args.range(value, "value", 1, 7);
    this.text = "level" + value;
  }

  @Override
  public String toString() {
    return "SecurityLevel: " + text;
  }

  public int getValue() {
      return value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new ASN1Enumerated(value);
  }

  public static SecurityLevel lookup(int value) {
    SecurityLevel ret = map.get(value);
    if (ret == null) {
      throw new IllegalArgumentException("invalid SecurityLevel " + value);
    }
    return ret;
  }
}
