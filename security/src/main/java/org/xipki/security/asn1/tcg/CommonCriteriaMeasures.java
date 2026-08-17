// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.*;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * CommonCriteriaMeasures ::= SEQUENCE {
 *     Version            IA5STRING (SIZE (1..STRMAX)),
 *                            -- “2.2” or “3.1”; future syntax defined by CC
 *     Assurancelevel     EvaluationAssuranceLevel,
 *     evaluationStatus   EvaluationStatus,
 *     plus               BOOLEAN DEFAULT FALSE,
 *     strengthOfFunction [0] IMPLICIT StrengthOfFunction OPTIONAL,
 *     profileOid         [1] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
 *     profileUri         [2] IMPLICIT URIReference OPTIONAL,
 *     targetOid          [3] IMPLICIT OBJECT IDENTIFIER OPTIONAL,
 *     targetUri          [4] IMPLICIT URIReference OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CommonCriteriaMeasures extends ASN1Object {

  private final String version;

  private final EvaluationAssuranceLevel assuranceLevel;

  private final EvaluationStatus evaluationStatus;

  private final boolean plus;

  private final StrengthOfFunction strengthOfFunction;

  private final ASN1ObjectIdentifier profileOid;

  private final URIReference profileUri;

  private final ASN1ObjectIdentifier targetOid;

  private final URIReference targetUri;

  public CommonCriteriaMeasures(
      String version, EvaluationAssuranceLevel assuranceLevel,
      EvaluationStatus evaluationStatus, boolean plus,
      StrengthOfFunction strengthOfFunction, ASN1ObjectIdentifier profileOid,
      URIReference profileUri, ASN1ObjectIdentifier targetOid, URIReference targetUri) {
    this.version = Args.lengthRange(version, "version", 1, TcgConstants.STRMAX);
    this.assuranceLevel = Args.notNull(assuranceLevel, "assuranceLevel");
    this.evaluationStatus = Args.notNull(evaluationStatus, "evaluationStatus");
    this.plus = plus;
    this.strengthOfFunction = strengthOfFunction;
    this.profileOid = profileOid;
    this.profileUri = profileUri;
    this.targetOid = targetOid;
    this.targetUri = targetUri;
  }

  public String version() {
    return version;
  }

  public EvaluationAssuranceLevel assuranceLevel() {
    return assuranceLevel;
  }

  public EvaluationStatus evaluationStatus() {
    return evaluationStatus;
  }

  public boolean plus() {
    return plus;
  }

  public StrengthOfFunction strengthOfFunction() {
    return strengthOfFunction;
  }

  public ASN1ObjectIdentifier profileOid() {
    return profileOid;
  }

  public URIReference profileUri() {
    return profileUri;
  }

  public ASN1ObjectIdentifier targetOid() {
    return targetOid;
  }

  public URIReference targetUri() {
    return targetUri;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(9);
    v.add(new DERIA5String(version));
    v.add(assuranceLevel);
    v.add(evaluationStatus);
    if (plus) {
      v.add(ASN1Boolean.TRUE);
    }

    if (strengthOfFunction != null) { // tag 0
      v.add(new DERTaggedObject(false, 0,  strengthOfFunction));
    }

    if (profileOid != null) { // tag 1
      v.add(new DERTaggedObject(false, 1,  profileOid));
    }

    if (profileUri != null) { // tag 2
      v.add(new DERTaggedObject(false, 2,  profileUri));
    }

    if (targetOid != null) { // tag 3
      v.add(new DERTaggedObject(false, 3,  targetOid));
    }

    if (targetUri != null) { // tag 4
      v.add(new DERTaggedObject(false, 4,  targetUri));
    }

    return new DERSequence(v);
  }

  public static CommonCriteriaMeasures getInstance(Object  obj) {
    if (obj instanceof CommonCriteriaMeasures) {
      return (CommonCriteriaMeasures) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 3) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      String version = Asn1Util.getIA5String(seq.getObjectAt(0));
      EvaluationAssuranceLevel assuranceLevel =
          EvaluationAssuranceLevel.getInstance(seq.getObjectAt(1));
      EvaluationStatus evaluationStatus = EvaluationStatus.getInstance(seq.getObjectAt(2));

      int index = 3;
      ASN1Encodable asn1 = seq.getObjectAt(index);
      boolean plus = false;
      if (asn1 instanceof ASN1Boolean) {
        plus = ((ASN1Boolean) asn1).isTrue();
        index++;
      }

      StrengthOfFunction strengthOfFunction = null;
      ASN1ObjectIdentifier profileOid = null;
      URIReference profileUri = null;
      ASN1ObjectIdentifier targetOid = null;
      URIReference targetUri = null;

      int minTagNo = 0;
      for (; index < size; index++) {
        ASN1TaggedObject tagObj = (ASN1TaggedObject) seq.getObjectAt(index);
        int tagNo = tagObj.getTagNo();
        if (tagNo < minTagNo) {
          throw new IllegalArgumentException("invalid occurrence of element with tag " + tagNo);
        }

        if (tagNo == 0) {
          strengthOfFunction = StrengthOfFunction.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.ENUMERATED));
        } else if (tagNo == 1) {
          profileOid = ASN1ObjectIdentifier.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.OBJECT_IDENTIFIER));
        } else if (tagNo == 2) {
          profileUri = URIReference.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else if (tagNo == 3) {
          targetOid = ASN1ObjectIdentifier.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.OBJECT_IDENTIFIER));
        } else if (tagNo == 4) {
          targetUri = URIReference.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else {
          throw new IllegalArgumentException("invalid tagNo " + tagNo);
        }

        minTagNo = tagNo + 1;

      }

      return new CommonCriteriaMeasures(version, assuranceLevel, evaluationStatus, plus,
          strengthOfFunction, profileOid, profileUri, targetOid, targetUri);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
