Deployment in Tomcat (8, 9 and 10)
----
1. Copy the war-files in `webapps` for tomcat 8/9 or `webapps-tomcat10on` for tomcat 10+,
   to the tomcat folder `${CATALINA_HOME}/webapps`:
    - In `${CATALINA_HOME}/webapps`, delete the folder `<some-app>` if the same named `<some-app>.war` file exists.
2. Copy (and overwrite if files already exist) the sub-folders `bin`, `xipki` and `lib `
   to the tomcat root folder `${CATALINA_HOME}`.
    - The folder `xipki` can be moved to other location, in this case the java property `XIPKI_BASE` in
      `setenv.sh` and `setenv.bat` must be adapted to point to the new position.
    - In `${CATALINA_HOME}/lib`, if an old version of a jar file exists, remove it first.
3. Configure the TLS listener in the file
   `${CATALINA_HOME}conf/server.xml` (we use here the port 8446, can be changed to any other port)
   Delete all non-TLS connectors, and add TLS connector as follows:
   ```sh
   <Connector port="8446" protocol="org.apache.coyote.http11.Http11Nio2Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               connectionTimeout="4000">
        <SSLHostConfig
                certificateVerification="optional"
                protocols="TLSv1.2+TLSv1.3"
                ciphers="TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256,TLS_AES_128_CCM_8_SHA256,TLS_AES_128_CCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                truststoreFile="${XIPKI_BASE}/keycerts/hsmproxy-client-certstore.p12"
                truststorePassword="CHANGEIT"
                truststoreType="PKCS12">
            <Certificate
                         certificateKeystoreFile="${XIPKI_BASE}/keycerts/hsmproxy-server.p12"
                         certificateKeystorePassword="CHANGEIT"
                         certificateKeystoreType="PKCS12"/>
        </SSLHostConfig>
   </Connector>
   ``` 
3. (optional) To accelerate the start process, append the following block to the property
`tomcat.util.scan.StandardJarScanFilter.jarsToSkip` in the file `conf/catalina.properties`.

```
bcpkix-*.jar,\
bcprov-*.jar,\
bcutil-*.jar,\
*pkcs11wrapper-*.jar,\
hsmproxy-*.jar,\
jackson-*.jar,\
password-*.jar,\
security-*.jar,\
servlet*-common-*.jar,\
util-*.jar,\
xipki-tomcat-password-*.jar
```

4. If you have multiple tomcat instances, change the listing port for SHUTDOW to be unique.

- Start tomcat

```sh
  bin/startup.sh
```