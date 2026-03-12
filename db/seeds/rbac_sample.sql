INSERT INTO roles (tenant_id, name) VALUES
('tenant-1', 'admin'),
('tenant-1', 'reader'),
('tenant-2', 'admin'),
('tenant-2', 'support')
ON CONFLICT DO NOTHING;

INSERT INTO permissions (name) VALUES
('orders:read'),
('orders:update'),
('orders:delete'),
('admin:delete'),
('tickets:read'),
('tickets:update')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE (r.name = 'admin' AND p.name IN ('orders:read','orders:update','orders:delete','admin:delete'))
   OR (r.name = 'reader' AND p.name = 'orders:read')
   OR (r.name = 'support' AND p.name IN ('tickets:read','tickets:update'))
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, tenant_id, role_id)
SELECT 'user-admin', r.tenant_id, r.id FROM roles r WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, tenant_id, role_id)
SELECT 'user-reader', r.tenant_id, r.id FROM roles r WHERE r.name = 'reader'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, tenant_id, role_id)
SELECT 'user-support', r.tenant_id, r.id FROM roles r WHERE r.name = 'support'
ON CONFLICT DO NOTHING;
