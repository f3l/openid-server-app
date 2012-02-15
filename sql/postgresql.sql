CREATE TABLE users (
  id integer NOT NULL,
  username varchar(128) NOT NULL,
  password varchar(128) DEFAULT NULL,
  email_address varchar(128) DEFAULT NULL,
  nickname varchar(128) DEFAULT NULL,
  fullname varchar(128) DEFAULT NULL,
  created timestamp DEFAULT 'now',
  logged timestamp DEFAULT NULL,
  is_manager smallint NOT NULL DEFAULT 0,
  is_enabled smallint NOT NULL DEFAULT 0
);

ALTER TABLE users ADD CONSTRAINT users_pk PRIMARY KEY (id);
CREATE UNIQUE INDEX users_username_uq ON users (username);

CREATE TABLE sessions (
  id char(32) NOT NULL,
  a_session text
);

ALTER TABLE sessions ADD CONSTRAINT sessions_pk PRIMARY KEY (id);
CREATE INDEX sessions_id_idx ON sessions (id);

CREATE TABLE secrets (
  timestamp integer NOT NULL,
  secret varchar(32) NOT NULL,
  created integer NOT NULL
);

ALTER TABLE secrets ADD CONSTRAINT secrets_pk PRIMARY KEY (timestamp, secret);

CREATE TABLE autologin (
  user_id integer NOT NULL,
  secret char(32) NOT NULL,
  expires integer NOT NULL
);

ALTER TABLE autologin ADD CONSTRAINT autologin_user_fk FOREIGN KEY (user_id) REFERENCES users (id);
CREATE INDEX autologin_user_id_idx ON autologin (user_id);

CREATE TABLE trusted (
  id integer NOT NULL,
  user_id integer NOT NULL,
  realm varchar(128) NOT NULL,
  authorized smallint NOT NULL DEFAULT '0',
  created timestamp DEFAULT 'now',
  logged timestamp NULL DEFAULT NULL
);

ALTER TABLE trusted ADD CONSTRAINT trusted_user_fk FOREIGN KEY (user_id) REFERENCES users (id);
ALTER TABLE trusted ADD CONSTRAINT trusted_pk PRIMARY KEY (id);
CREATE UNIQUE INDEX trusted_realm_uq ON trusted (realm, user_id);
CREATE INDEX trusted_user_id_idx ON trusted (user_id);

CREATE TABLE log (
  user_id integer NOT NULL,
  trusted_id integer DEFAULT NULL,
  logged timestamp DEFAULT 'now',
  ip_address varchar(128) NOT NULL,
  useragent varchar(1024) DEFAULT NULL
);

ALTER TABLE log ADD CONSTRAINT log_trusted_fk FOREIGN KEY (trusted_id) REFERENCES trusted (id);
ALTER TABLE log ADD CONSTRAINT log_user_fk FOREIGN KEY (user_id) REFERENCES users (id);
CREATE INDEX log_trusted_id_idx ON log (trusted_id);
CREATE INDEX log_user_id_idx ON log (user_id);

CREATE SEQUENCE users_id_seq INCREMENT BY 1 MINVALUE 1 NO MAXVALUE CACHE 1;
CREATE SEQUENCE trusted_id_seq INCREMENT BY 1 MINVALUE 1 NO MAXVALUE CACHE 1;

CREATE LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION set_primary_key() RETURNS TRIGGER  AS '
    DECLARE
        new_id INTEGER;
        new_id_counter INTEGER := 0;
    BEGIN
        IF new.id IS NULL THEN
            LOOP
                SELECT nextval(tg_relname||''_id_seq'') INTO new_id;
                SELECT COUNT(*) INTO new_id_counter FROM users WHERE id = new_id;
                EXIT WHEN new_id_counter = 0;
            END LOOP;

            new.id = new_id;
        END IF;
        RETURN new;
    END;
' LANGUAGE plpgsql;

CREATE TRIGGER users_bifer_trigger BEFORE INSERT ON users FOR EACH ROW EXECUTE PROCEDURE set_primary_key();
CREATE TRIGGER trusted_bifer_trigger BEFORE INSERT ON trusted FOR EACH ROW EXECUTE PROCEDURE set_primary_key();

