// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * The following attributes has attribute value of type Traits defined in this class:
 * <ul>
 *   <li>PreviousPlatformCertificates</li>
 *   <li>cryptographicAnchors</li>
 *   <li>tBBSecurityAssertions</li>
 *   <li>ComponentIdentifier</li>
 *   <li>PlatformConfigUri-v3</li>
 *   <li>PlatformOwnership</li>
 * </ul>
 *
 * <pre>
 * Traits ::= SEQUENCE(SIZE(1..MAX) OF Trait
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Traits extends ASN1Object {

  private final List<Trait> traits;

  public Traits(List<Trait> traits) {
    this.traits = Args.notEmptyAndNoNullElements(traits, "traits");
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(traits.toArray(new Trait[0]));
  }

  public static Traits getInstance(Object  obj) {
    if (obj instanceof Traits) {
      return (Traits) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      List<Trait> traits = new ArrayList<>(size);
      for (int i = 0; i < size; i++) {
        ASN1Encodable ele = seq.getObjectAt(i);
        traits.add(Trait.getInstance(ele));
      }
      return new Traits(traits);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
