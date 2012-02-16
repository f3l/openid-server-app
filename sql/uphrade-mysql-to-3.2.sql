DELIMITER //
CREATE FUNCTION upsert_trusted (new_user_id int(32) unsigned, new_realm varchar(128))
RETURNS int(1)
BEGIN
    INSERT IGNORE INTO trusted (user_id, realm, authorized, created, logged)
                        VALUES (new_user_id, new_realm, 1, NOW(), NOW());
    RETURN 0;
END//
DELIMITER ;

