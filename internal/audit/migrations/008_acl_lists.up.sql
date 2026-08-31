-- CIDR access control lists, moved out of config.json so they can be changed
-- on a running server. One row per entry; acl_lists records which lists the
-- database owns.
--
-- acl_lists exists because "no rows in acl_entries" is two different answers
-- for trusted_proxies: an operator who wrote [] disabled header trust, and one
-- who wrote nothing takes the built-in loopback + RFC 1918 default. A list with
-- a row here is answered from the table even when it is empty; a list without
-- one is still answered from the config file.
CREATE TABLE IF NOT EXISTS acl_lists (
    list      TEXT PRIMARY KEY CHECK(list IN ('admin','deny','proxies')),
    seeded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS acl_entries (
    list       TEXT NOT NULL CHECK(list IN ('admin','deny','proxies')),
    cidr       TEXT NOT NULL,
    comment    TEXT DEFAULT '',
    actor      TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (list, cidr)
);
