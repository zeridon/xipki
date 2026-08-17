// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * TNAuthorizationList ::= SEQUENCE SIZE (1..MAX) OF TNEntry
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TNAuthorizationList extends ASN1Object {

  private final List<TNEntry> entries;

  public TNAuthorizationList(List<TNEntry> entries) {
    this.entries = Args.notEmptyAndNoNullElements(entries, "entries");
  }

  public List<TNEntry> getEntries() {
    return entries;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (TNEntry m : entries) {
      v.add(m.toASN1Primitive());
    }
    return new DERSequence(v);
  }

  public static TNAuthorizationList getInstance(Object  obj) {
    if (obj instanceof TNAuthorizationList) {
      return (TNAuthorizationList) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      List<TNEntry> entries = new ArrayList<>(seq.size());
      for (int i = 0; i < seq.size(); i++) {
        entries.add(TNEntry.getInstance(seq.getObjectAt(i)));
      }
      return new TNAuthorizationList(entries);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
