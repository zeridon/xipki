// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.*;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * CommonCriteriaEvaluation ::= SEQUENCE {
 *     cCMeasures                CommonCriteriaMeasures,
 *     cCCertificateNumber       UTF8String (SIZE (1..STRMAX)),
 *     cCCertificateAuthority    UTF8String (SIZE (1..STRMAX)),
 *     evaluationScheme          [0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     cCCertificateIssuanceDate [1] IMPLICIT GeneralizedTime OPTIONAL,
 *     cCCertificateExpiryDate   [2] IMPLICIT GeneralizedTime OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CommonCriteriaEvaluation extends ASN1Object {

  private final CommonCriteriaMeasures cCMeasures;

  private final String cCCertificateNumber;

  private final String cCCertificateAuthority;

  private final String evaluationScheme;

  private final ASN1GeneralizedTime cCCertificateIssuanceDate;

  private final ASN1GeneralizedTime cCCertificateExpiryDate;

  public CommonCriteriaEvaluation(
      CommonCriteriaMeasures cCMeasures, String cCCertificateNumber,
      String cCCertificateAuthority, String evaluationScheme,
      ASN1GeneralizedTime cCCertificateIssuanceDate,
      ASN1GeneralizedTime cCCertificateExpiryDate) {
    this.cCMeasures = Args.notNull(cCMeasures, "cCMeasures");
    this.cCCertificateNumber = Args.notNull(cCCertificateNumber, "cCCertificateNumber");
    this.cCCertificateAuthority = Args.notNull(cCCertificateAuthority, "cCCertificateAuthority");
    this.evaluationScheme = evaluationScheme;
    this.cCCertificateIssuanceDate = cCCertificateIssuanceDate;
    this.cCCertificateExpiryDate = cCCertificateExpiryDate;
  }

  public CommonCriteriaMeasures cCMeasures() {
    return cCMeasures;
  }

  public String cCCertificateNumber() {
    return cCCertificateNumber;
  }

  public String cCCertificateAuthority() {
    return cCCertificateAuthority;
  }

  public String evaluationScheme() {
    return evaluationScheme;
  }

  public ASN1GeneralizedTime cCCertificateIssuanceDate() {
    return cCCertificateIssuanceDate;
  }

  public ASN1GeneralizedTime cCCertificateExpiryDate() {
    return cCCertificateExpiryDate;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(6);
    v.add(cCMeasures);
    v.add(new DERUTF8String(cCCertificateNumber));
    v.add(new DERUTF8String(cCCertificateAuthority));
    if (evaluationScheme != null) {
      v.add(new DERTaggedObject(false, 0, new DERUTF8String(evaluationScheme)));
    }

    if (cCCertificateIssuanceDate != null) {
      v.add(new DERTaggedObject(false, 1, cCCertificateIssuanceDate));
    }

    if (cCCertificateExpiryDate != null) {
      v.add(new DERTaggedObject(false, 2, cCCertificateExpiryDate));
    }
    return new DERSequence(v);
  }

  public static CommonCriteriaEvaluation getInstance(Object  obj) {
    if (obj instanceof CommonCriteriaEvaluation) {
      return (CommonCriteriaEvaluation) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 3) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      CommonCriteriaMeasures measures = CommonCriteriaMeasures.getInstance(seq.getObjectAt(0));
      String cCCertificateNumber = Asn1Util.getUTF8String(seq.getObjectAt(1));
      String cCCertificateAuthority = Asn1Util.getUTF8String(seq.getObjectAt(2));

      String evaluationScheme = null;
      ASN1GeneralizedTime cCCertificateIssuanceDate = null;
      ASN1GeneralizedTime cCCertificateExpiryDate = null;

      int index = 3;
      int minTagNo = 0;
      for (; index < size; index++) {
        ASN1TaggedObject tagObj = (ASN1TaggedObject) seq.getObjectAt(index);
        int tagNo = tagObj.getTagNo();
        if (tagNo < minTagNo) {
          throw new IllegalArgumentException("invalid occurrence of element with tag " + tagNo);
        }

        if (tagNo == 0) {
          evaluationScheme = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.UTF8_STRING));
        } else if (tagNo == 1) {
          cCCertificateIssuanceDate = ASN1GeneralizedTime.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.GENERALIZED_TIME));
        } else if (tagNo == 2) {
          cCCertificateExpiryDate = ASN1GeneralizedTime.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.GENERALIZED_TIME));
        } else {
          throw new IllegalArgumentException("invalid tagNo " + tagNo);
        }

        minTagNo = tagNo + 1;

      }

      return new CommonCriteriaEvaluation(measures, cCCertificateNumber, cCCertificateAuthority,
          evaluationScheme, cCCertificateIssuanceDate, cCCertificateExpiryDate);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
