CREATE TABLE `users` (
  `id` int(32) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(128) NOT NULL,
  `password` varchar(128) DEFAULT NULL,
  `email_address` varchar(128) DEFAULT NULL,
  `nickname` varchar(128) DEFAULT NULL,
  `fullname` varchar(128) DEFAULT NULL,
  `created` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `logged` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `is_manager` int(1) NOT NULL DEFAULT 0,
  `is_enabled` int(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `users_username_idx` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `sessions` (
  `id` char(32) NOT NULL,
  `a_session` text,
  PRIMARY KEY (`id`),
  KEY `sessions_id_idx` (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `secrets` (
  `timestamp` int(32) unsigned NOT NULL,
  `secret` varchar(32) NOT NULL,
  `created` int(32) unsigned NOT NULL,
  PRIMARY KEY (`timestamp`,`secret`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `autologin` (
  `user_id` int(32) unsigned NOT NULL,
  `secret` char(32) NOT NULL,
  `expires` int(32) unsigned NOT NULL,
  KEY `autologin_user_fk` (`user_id`),
  CONSTRAINT `autologin_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `trusted` (
  `id` int(32) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(32) unsigned NOT NULL,
  `realm` varchar(128) NOT NULL,
  `authorized` int(1) NOT NULL DEFAULT '0',
  `created` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `logged` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trusted_realm_uq` (`realm`, `user_id`),
  KEY `trusted_user_id_fk` (`user_id`),
  CONSTRAINT `trusted_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `log` (
  `user_id` int(32) unsigned NOT NULL,
  `trusted_id` int(32) unsigned DEFAULT NULL,
  `logged` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `ip_address` varchar(128) NOT NULL,
  `useragent` varchar(1024) DEFAULT NULL,
  KEY `log_trusted_id_fk` (`trusted_id`),
  KEY `log_user_id_fk` (`user_id`),
  CONSTRAINT `log_trusted_id_fk` FOREIGN KEY (`trusted_id`) REFERENCES `trusted` (`id`),
  CONSTRAINT `log_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DELIMITER //
CREATE FUNCTION insert_trusted (new_user_id int(32) unsigned, new_realm varchar(128))
RETURNS int(1)
BEGIN
    INSERT IGNORE INTO trusted (user_id, realm, authorized, created, logged)
                        VALUES (new_user_id, new_realm, 1, NOW(), NOW());
    RETURN 0;
END//
DELIMITER ;

