-- IGNORE-ERROR
ALTER TABLE ORDER2 DROP CONSTRAINT FK_ORDER_ACCOUNT1;

DROP TABLE IF EXISTS DBSCHEMA;
DROP TABLE IF EXISTS ACCOUNT;
DROP TABLE IF EXISTS ORDER2;

-- changeset xipki:1
CREATE TABLE DBSCHEMA (
    NAME VARCHAR(45) NOT NULL,
    VALUE2 VARCHAR(100) NOT NULL,
    CONSTRAINT PK_DBSCHEMA PRIMARY KEY (NAME)
);

COMMENT ON TABLE DBSCHEMA IS 'database schema information';

INSERT INTO DBSCHEMA (NAME, VALUE2) VALUES ('VENDOR', 'XIPKI');

INSERT INTO DBSCHEMA (NAME, VALUE2) VALUES ('VERSION', '1');

CREATE TABLE ACCOUNT (
    ID BIGINT NOT NULL,
    LUPDATE BIGINT NOT NULL,
    STATUS SMALLINT NOT NULL,
    JWK_SHA256 CHAR(43) NOT NULL,
    DATA VARCHAR(2000) NOT NULL,
    CONSTRAINT PK_ACCOUNT PRIMARY KEY (ID)
 );

COMMENT ON COLUMN ACCOUNT.LUPDATE IS 'last update, seconds since January 1, 1970, 00:00:00 GMT';

CREATE TABLE ORDER2 (
    ID BIGINT NOT NULL,
    LUPDATE BIGINT NOT NULL,
    ACCOUNT_ID BIGINT NOT NULL,
    STATUS SMALLINT NOT NULL,
    EXPIRES BIGINT NOT NULL,
    CERT_NAFTER BIGINT,
    CERT_SHA256 CHAR(43),
    AUTHZS VARCHAR(2000) NOT NULL,
    CERTREQ_META VARCHAR(200),
    CSR VARCHAR(2000),
    CERT VARCHAR(3000),
    CONSTRAINT PK_ORDER2 PRIMARY KEY (ID)
);

COMMENT ON COLUMN ORDER2.LUPDATE IS 'last update, seconds since January 1, 1970, 00:00:00 GMT';

-- changeset xipki:2
ALTER TABLE ORDER2 ADD CONSTRAINT FK_ORDER_ACCOUNT1
    FOREIGN KEY (ACCOUNT_ID) REFERENCES ACCOUNT (ID)
    ON UPDATE NO ACTION ON DELETE NO ACTION;
