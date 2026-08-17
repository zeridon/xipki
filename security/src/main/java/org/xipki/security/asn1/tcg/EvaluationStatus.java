// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.xipki.util.codec.Args;

import java.util.HashMap;

/**
 * The EvaluationStatus enumeration.
 * <pre>
 * EvaluationStatus ::= ENUMERATED {
 *     designedToMeet       (0),
 *     evaluationInProgress (1),
 *     evaluationCompleted  (2)
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EvaluationStatus extends ASN1Object {

  private static final HashMap<Integer, EvaluationStatus> map = new HashMap<>();

  public static final EvaluationStatus designedToMeet = f(0);
  public static final EvaluationStatus evaluationInProgress = f(1);
  public static final EvaluationStatus evaluationCompleted = f(2);

  private final int value;

  private final String text;

  private static EvaluationStatus f(int value) {
    EvaluationStatus asn1 = new EvaluationStatus(value);
    map.put(value, asn1);
    return asn1;
  }

  public static EvaluationStatus getInstance(Object o) {
    Args.notNull(o, "o");
    if (o instanceof EvaluationStatus) {
      return (EvaluationStatus)o;
    } else {
      return lookup(ASN1Enumerated.getInstance(o).intValueExact());
    }
  }

  private EvaluationStatus(int value) {
    this.value = Args.range(value, "value", 0, 2);
    switch (value) {
      case 0:
        this.text = "designedToMeet";
        break;
      case 1:
        this.text = "evaluationInProgress";
        break;
      default:
        this.text = "evaluationCompleted";
    }
  }

  @Override
  public String toString() {
    return  "EvaluationStatus: " + text;
  }

  public int getValue() {
      return value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new ASN1Enumerated(value);
  }

  public static EvaluationStatus lookup(int value) {
    EvaluationStatus ret = map.get(value);
    if (ret == null){
      throw new IllegalArgumentException("invalid EvaluationStatus " + value);
    }
    return ret;
  }
}
