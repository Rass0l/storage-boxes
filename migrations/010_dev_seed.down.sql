DELETE FROM role_bindings WHERE user_id = 'usr_seed_admin' AND role_name = 'admin';
DELETE FROM user_credentials WHERE user_id = 'usr_seed_admin';
DELETE FROM users WHERE id = 'usr_seed_admin';
DELETE FROM roles WHERE name = 'admin';
