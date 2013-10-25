--
-- ejabberd, Copyright (C) 2002-2011   ProcessOne
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License as
-- published by the Free Software Foundation; either version 2 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
-- 02111-1307 USA
--

-- Needs MySQL (at least 4.0.x) with innodb back-end

CREATE TABLE mam_messages(
  -- Message UID
  -- A server-assigned UID that MUST be unique within the archive.
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  local_username varchar(128) NOT NULL,
  from_jid varchar(128) NOT NULL,
  -- The remote JID that the stanza is to (for an outgoing message) or from (for an incoming message).
  remote_bare_jid varchar(128) NOT NULL,
  remote_resource varchar(16) NOT NULL,
  -- I - incoming, remote_jid is a value from From.
  -- O - outgoing, remote_jid is a value from To.
  direction character(1) NOT NULL,
  -- A miliseconds-resolution timestamp of when the message was sent (for an outgoing message)
  -- or received (for an incoming message).
  -- added_at timestamp NOT NULL,
  added_at BIGINT NOT NULL,
  -- Term-encoded message
  message blob NOT NULL
);
CREATE INDEX i_mam_messages_username_added_at USING BTREE ON mam_messages(local_username, added_at);
CREATE INDEX i_mam_messages_username_jid_added_at USING BTREE ON mam_messages(local_username, remote_bare_jid, added_at);

CREATE TABLE mam_messages_counts(
  local_username varchar(128) NOT NULL,
  remote_bare_jid varchar(128) NOT NULL,
  -- I - incoming, remote_jid is a value from From.
  -- O - outgoing, remote_jid is a value from To.
  direction character(1) NOT NULL,
);
CREATE INDEX i_mam_messages_counts_username USING BTREE ON mam_messages(local_username);
CREATE INDEX i_mam_messages_counts_username_jid USING BTREE ON mam_messages(local_username, remote_bare_jid);


CREATE TABLE mam_config(
  local_username varchar(128) NOT NULL,
  -- If empty, than it is a default behaviour.
  remote_jid varchar(128) NOT NULL,
  -- A - always archive;
  -- N - newer archive;
  -- R - roster (only for remote_jid == "")
  behaviour character(1) NOT NULL
);
CREATE INDEX i_mam_config USING HASH ON mam_config(local_username, remote_jid);
