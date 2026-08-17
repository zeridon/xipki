package org.xipki.ca.certprofile.test;

import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.util.codec.Hex;
import org.xipki.util.io.IoUtil;

import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class DummyMain {

  public static void main(String[] args) {
    try {
      String s1 = ("a02b0608 2b060105 05070809 a01f0c1d e58cbb e7949f 4078 6e2d2d70" +
          "73733235 632e6578 616d706c 652e636f 6d").replace(" ", "");
      byte[] v1 = Hex.decode(s1);
      IoUtil.save("target/smtpmailbox-1.der", v1);

      String s = "医生";
      byte[] v =  s.getBytes(StandardCharsets.UTF_8);
      System.out.println(Hex.encode(v));
      IoUtil.save("target/smtpmailbox.der", v);

      byte[] v2 =  new DERUTF8String(s).getEncoded();
      System.out.println(Hex.encode(v2));
      IoUtil.save("target/smtpmailbox-2.der", v2);

      String result = s.codePoints()
              .mapToObj(cp -> cp < 0x80
                      ? String.valueOf((char) cp)
                      : String.format("U+%04X", cp))
              .collect(Collectors.joining());
      //System.out.println(result);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
