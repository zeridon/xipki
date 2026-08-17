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
 * EvaluationAssuranceLevel ::= ENUMERATED {
 *     level1 (1),
 *     level2 (2),
 *     level3 (3),
 *     level4 (4),
 *     level5 (5),
 *     level6 (6),
 *     level7 (7)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EvaluationAssuranceLevel extends ASN1Object {

  private static final HashMap<Integer, EvaluationAssuranceLevel> map = new HashMap<>();

  public static final EvaluationAssuranceLevel level1 = f(1);
  public static final EvaluationAssuranceLevel level2 = f(2);
  public static final EvaluationAssuranceLevel level3 = f(3);
  public static final EvaluationAssuranceLevel level4 = f(4);
  public static final EvaluationAssuranceLevel level5 = f(5);
  public static final EvaluationAssuranceLevel level6 = f(6);
  public static final EvaluationAssuranceLevel level7 = f(7);

  private final int value;

  private final String text;

  private static EvaluationAssuranceLevel f(int value) {
    EvaluationAssuranceLevel asn1 = new EvaluationAssuranceLevel(value);
    map.put(value, asn1);
    return asn1;
  }

  public static EvaluationAssuranceLevel getInstance(Object o) {
    if (o instanceof EvaluationAssuranceLevel) {
      return (EvaluationAssuranceLevel)o;
    } else if (o != null) {
      return lookup(ASN1Enumerated.getInstance(o).intValueExact());
    }

    return null;
  }

  private EvaluationAssuranceLevel(int value) {
    this.value = Args.range(value, "value", 1, 7);
    this.text = "level" + value;
  }

  @Override
  public String toString() {
    return "EvaluationAssuranceLevel: " + text;
  }

  public int getValue() {
      return value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new ASN1Enumerated(value);
  }

  public static EvaluationAssuranceLevel lookup(int value) {
    EvaluationAssuranceLevel ret = map.get(value);
    if (ret == null) {
      throw new IllegalArgumentException("invalid EvaluationAssuranceLevel " + value);
    }
    return ret;
  }
}
