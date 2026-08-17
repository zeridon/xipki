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
 * ComponentAddresses ::= SEQUENCE(SIZE(1..MAX) OF ComponentAddress
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentAddresses extends ASN1Object {

  private final List<ComponentAddress> addresses;

  public ComponentAddresses(List<ComponentAddress> addresses) {
    this.addresses = Args.notEmptyAndNoNullElements(addresses, "addresses");
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(addresses.toArray(new ComponentAddress[0]));
  }

  public static ComponentAddresses getInstance(Object  obj) {
    if (obj instanceof ComponentAddresses) {
      return (ComponentAddresses) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      List<ComponentAddress> addresses = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        addresses.add(ComponentAddress.getInstance(seq.getObjectAt(i)));
      }
      return new ComponentAddresses(addresses);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
