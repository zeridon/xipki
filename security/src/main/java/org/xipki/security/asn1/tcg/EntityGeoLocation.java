// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.*;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * entityGeoLocationTrait TRAIT ::= {
 *     SYNTAX EntityGeoLocation
 *     IDENTIFIED BY tcg-tr-ID-entGeoLocation
 * }
 *
 * ISO3166CountryCode ::= PrintableString (SIZE(2..3))
 *
 * ISO3166AdminSubdivisionCode ::= PrintableString (SIZE (3..6))
 *
 * OpenLocationCode ::= PrintableString
 *
 * EntityGeoLocation ::= SEQUENCE {
 *     countryCode     ISO3166CountryCode,
 *     stateOrProvince [0] IMPLICIT ISO3166AdminSubdivisionCode OPTIONAL,
 *     localityName    [1] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     streetAddress   [2] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     locationCoords  [3] IMPLICIT OpenLocationCode OPTIONAL,
 *     postalCode      [5] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EntityGeoLocation extends ASN1Object {

  private final String countryCode;

  private final String stateOrProvince;

  private final String localityName;

  private final String streetAddress;

  private final String locationCoords;

  private final String postalCode;

  public EntityGeoLocation(String countryCode, String stateOrProvince,
                           String localityName, String streetAddress,
                           String locationCoords, String postalCode) {
    this.countryCode = Args.lengthRange(countryCode, "countryCode", 2, 3);

    if (stateOrProvince != null) {
      Args.lengthRange(stateOrProvince, "stateOrProvince", 3, 6);
    }
    this.stateOrProvince = stateOrProvince;

    if (localityName != null) {
      Args.lengthRange(localityName, "localityName", 1, TcgConstants.STRMAX);
    }
    this.localityName = localityName;

    if (streetAddress != null) {
      Args.lengthRange(streetAddress, "streetAddress", 1, TcgConstants.STRMAX);
    }
    this.streetAddress = streetAddress;

    if (locationCoords != null) {
      Args.lengthRange(locationCoords, "locationCoords", 3, 6);
    }
    this.locationCoords = locationCoords;

    if (postalCode != null) {
      Args.lengthRange(postalCode, "postalCode", 1, TcgConstants.STRMAX);
    }
    this.postalCode = postalCode;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(6);
    v.add(new DERPrintableString(countryCode));

    if (stateOrProvince != null) {
      v.add(new DERPrintableString(stateOrProvince));
    }

    if (localityName != null) {
      v.add(new DERUTF8String(localityName));
    }

    if (streetAddress != null) {
      v.add(new DERUTF8String(streetAddress));
    }

    if (locationCoords != null) {
      v.add(new DERPrintableString(locationCoords));
    }

    if (postalCode != null) {
      v.add(new DERUTF8String(postalCode));
    }

    return new DERSequence(v);
  }

  public static EntityGeoLocation getInstance(Object  obj) {
    if (obj instanceof EntityGeoLocation) {
      return (EntityGeoLocation) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 1 || size > 6) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      String countryCode = Asn1Util.getIA5String(seq.getObjectAt(0));

      String stateOrProvince = null;
      String localityName = null;
      String streetAddress = null;
      String locationCoords = null;
      String postalCode = null;

      int index = 1;
      int minTagNo = 0;
      for (; index < size; index++) {
        ASN1TaggedObject tagObj = (ASN1TaggedObject) seq.getObjectAt(index);
        int tagNo = tagObj.getTagNo();
        if (tagNo < minTagNo) {
          throw new IllegalArgumentException("invalid occurrence of element with tag " + tagNo);
        }

        if (tagNo == 0) {
          stateOrProvince = Asn1Util.getPrintableString(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.PRINTABLE_STRING));
        } else if (tagNo == 1) {
          localityName = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.UTF8_STRING));
        } else if (tagNo == 2) {
          streetAddress = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.UTF8_STRING));
        } else if (tagNo == 3) {
          locationCoords = Asn1Util.getPrintableString(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.PRINTABLE_STRING));
        } else if (tagNo == 5) {
          postalCode = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.UTF8_STRING));
        } else {
          throw new IllegalArgumentException("invalid tagNo " + tagNo);
        }

        minTagNo = tagNo + 1;
      }

      return new EntityGeoLocation(countryCode, stateOrProvince,
          localityName, streetAddress, locationCoords, postalCode);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
