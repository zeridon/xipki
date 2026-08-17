// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * Properties ::= SEQUENCE(SIZE(1..MAX) OF Property
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Properties extends ASN1Object {

  private final List<Property> properties;

  public Properties(List<Property> properties) {
    this.properties = Args.notEmptyAndNoNullElements(properties, "properties");
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(properties.toArray(new Property[0]));
  }

  public static Properties getInstance(Object  obj) {
    if (obj instanceof Properties) {
      return (Properties) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      List<Property> properties = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        properties.add(Property.getInstance(seq.getObjectAt(i)));
      }
      return new Properties(properties);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
