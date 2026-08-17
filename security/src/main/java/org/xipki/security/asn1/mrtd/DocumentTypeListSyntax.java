// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1.mrtd;

import org.bouncycastle.asn1.*;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * ocumentTypeList EXTENSION ::= {
 *     SYNTAX     DocumentTypeListSyntax
 *     IDENTIFIED BY id-icao-mrtd-security-extensions-documentTypeList }
 *
 * DocumentTypeListSyntax ::= SEQUENCE {
 *     version     DocumentTypeListVersion,
 *     docTypeList SET OF DocumentType }
 *
 * DocumentTypeListVersion ::= INTEGER {v0(0)}
 * -- Document Type as contained in MRZ, e.g. “P” or “ID” where a
 * -- single letter denotes all document types starting with that letter
 *
 * DocumentType ::= PrintableString(SIZE(1..2))
 *
 * id-icao-mrtd-security-extensions-documentTypeList OBJECT
 *     IDENTIFIER ::= {id-icao-mrtd-security-extensions 2}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class DocumentTypeListSyntax extends ASN1Object {

  private final List<String> docTypeList;

  public DocumentTypeListSyntax(List<String> docTypeList) {
    this.docTypeList = Args.notNull(docTypeList, "docTypeList");
    for (String m : docTypeList) {
      if (m == null || (m.length() != 1 && m.length() != 2)) {
        throw new IllegalArgumentException("invalid docType '" + m + "'");
      }
    }
  }

  private DocumentTypeListSyntax(ASN1Sequence seq) {
    if (seq.size() != 2) {
      throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    int version = ((ASN1Integer) seq.getObjectAt(0)).intValueExact();
    if (version != 0) {
      throw new IllegalArgumentException("invalid version " + version);
    }

    ASN1Set set = (ASN1Set) seq.getObjectAt(1);
    List<String> docTypeList = new ArrayList<>(set.size());
    for (int i = 0; i < set.size(); i++) {
      docTypeList.add(Asn1Util.getPrintableString(set.getObjectAt(i)));
    }
    this.docTypeList = docTypeList;
  }

  public List<String> docTypeList() {
    return docTypeList;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (String m : docTypeList) {
      v.add(new DERPrintableString(m));
    }

    return new DERSequence(new ASN1Encodable[]{new ASN1Integer(BigInteger.ZERO), new DERSet(v)});
  }

  public static DocumentTypeListSyntax getInstance(Object obj) {
    if (obj instanceof DocumentTypeListSyntax) {
      return (DocumentTypeListSyntax) obj;
    } else if (obj instanceof ASN1Sequence) {
      return new DocumentTypeListSyntax((ASN1Sequence) obj);
    } else if (obj != null) {
      return new DocumentTypeListSyntax(ASN1Sequence.getInstance(obj));
    } else {
      throw new IllegalArgumentException("invalid obj: null");
    }
  }

}
