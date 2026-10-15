
-- ZAVO Marketplace Complete Database Schema
-- File: schema.sql
-- Target: Cloudflare D1 / SQLite
-- Database: zavo-stores-db
--
-- IMPORTANT:
-- FOR NEW/EMPTY DATABASES ONLY.
-- CREATE TABLE IF NOT EXISTS does not add columns to existing tables.
-- Use additive migrations for a live database.
-- IDs are supplied by the application (for example, crypto.randomUUID()).
-- REAL monetary columns are retained for compatibility with the current Worker.
-- A future redesign should use integer minor currency units consistently.

PRAGMA foreign_keys = ON;

-- 1. Users and roles
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer'
        CHECK (role IN ('customer', 'vendor', 'reseller', 'admin')),
    name TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Vendor accounts
CREATE TABLE IF NOT EXISTS vendors (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    shop_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'suspended')),
    documents_url TEXT,
    contact_phone TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

-- 3. Vendor applications and onboarding documents
CREATE TABLE IF NOT EXISTS vendor_applications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    business_name TEXT NOT NULL,
    reg_number TEXT,
    kra_pin TEXT,
    contact_email TEXT,
    id_document_url TEXT,
    permit_document_url TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'needs_information')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

-- 4. Products
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL CHECK (price >= 0),
    stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'pending', 'active', 'archived', 'rejected')),
    category TEXT NOT NULL DEFAULT 'General',
    colors TEXT,
    rating REAL,
    review TEXT,
    images TEXT,
    videos TEXT,
    reviews TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE RESTRICT
);

-- 5. Orders and checkout
CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    customer_name TEXT NOT NULL DEFAULT '',
    customer_email TEXT NOT NULL,
    customer_phone TEXT,
    county TEXT NOT NULL DEFAULT '',
    town TEXT NOT NULL DEFAULT '',
    shipping_address TEXT,
    delivery_address TEXT NOT NULL DEFAULT '',
    items_json TEXT NOT NULL DEFAULT '[]',
    subtotal REAL NOT NULL DEFAULT 0 CHECK (subtotal >= 0),
    shipping_cost REAL NOT NULL DEFAULT 0 CHECK (shipping_cost >= 0),
    total_amount REAL NOT NULL CHECK (total_amount >= 0),
    payment_method TEXT NOT NULL DEFAULT 'card',
    payment_status TEXT NOT NULL DEFAULT 'pending_payment'
        CHECK (payment_status IN ('pending_payment', 'pending', 'paid', 'failed', 'refunded')),
    fulfilment_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (fulfilment_status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
    paystack_reference TEXT UNIQUE,
    paid_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 6. Order line items
CREATE TABLE IF NOT EXISTS order_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price REAL NOT NULL CHECK (unit_price >= 0),
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT,
    FOREIGN KEY (vendor_id) REFERENCES vendors(id) ON DELETE RESTRICT
);

-- 7. Basic product referral links
CREATE TABLE IF NOT EXISTS referrals (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    referral_code TEXT NOT NULL UNIQUE,
    clicks INTEGER NOT NULL DEFAULT 0 CHECK (clicks >= 0),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
);

-- 8. Basic commissions ledger
CREATE TABLE IF NOT EXISTS commissions (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    order_id TEXT NOT NULL,
    amount REAL NOT NULL CHECK (amount >= 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'payable', 'paid', 'reversed')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE RESTRICT,
    UNIQUE (reseller_id, order_id)
);

-- 9. Reseller accounts and approval status
CREATE TABLE IF NOT EXISTS reseller_accounts (
    user_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'suspended')),
    commission_rate REAL NOT NULL DEFAULT 5.0
        CHECK (commission_rate >= 0 AND commission_rate <= 100),
    approved_by TEXT,
    approved_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
);

-- 10. Reseller referral codes
CREATE TABLE IF NOT EXISTS referral_codes (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    product_id TEXT,
    referral_code TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    clicks INTEGER NOT NULL DEFAULT 0 CHECK (clicks >= 0),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
);

-- 11. Referral click analytics
CREATE TABLE IF NOT EXISTS referral_clicks (
    id TEXT PRIMARY KEY,
    referral_code_id TEXT,
    referral_code TEXT NOT NULL,
    reseller_id TEXT NOT NULL,
    product_id TEXT,
    ip_hash TEXT,
    user_agent TEXT,
    landing_path TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (referral_code_id) REFERENCES referral_codes(id) ON DELETE SET NULL,
    FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
);

-- 12. Order attribution to a reseller
CREATE TABLE IF NOT EXISTS order_referrals (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL UNIQUE,
    reseller_id TEXT NOT NULL,
    referral_code TEXT NOT NULL,
    referral_code_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (referral_code_id) REFERENCES referral_codes(id) ON DELETE SET NULL
);

-- 13. Reseller commission lifecycle
CREATE TABLE IF NOT EXISTS reseller_commissions (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    order_id TEXT NOT NULL,
    order_referral_id TEXT,
    basis_amount REAL NOT NULL DEFAULT 0 CHECK (basis_amount >= 0),
    commission_rate REAL NOT NULL CHECK (commission_rate >= 0 AND commission_rate <= 100),
    amount REAL NOT NULL CHECK (amount >= 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'payable', 'paid', 'reversed')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE RESTRICT,
    FOREIGN KEY (order_referral_id) REFERENCES order_referrals(id) ON DELETE SET NULL,
    UNIQUE (order_id)
);

-- 14. Authentication sessions
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 15. Admin credentials / WebAuthn metadata, if used
CREATE TABLE IF NOT EXISTS admin_credentials (
    id TEXT PRIMARY KEY,
    email TEXT,
    password_hash TEXT,
    session_key TEXT,
    public_key TEXT,
    credential_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 16. Security and administrative audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 17. Query-performance indexes
CREATE INDEX IF NOT EXISTS idx_users_role
    ON users(role);

CREATE INDEX IF NOT EXISTS idx_vendors_status
    ON vendors(status);

CREATE INDEX IF NOT EXISTS idx_vendor_applications_user_status
    ON vendor_applications(user_id, status);

CREATE INDEX IF NOT EXISTS idx_products_status_created
    ON products(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_products_category_status
    ON products(category, status);

CREATE INDEX IF NOT EXISTS idx_products_vendor_status
    ON products(vendor_id, status);

CREATE INDEX IF NOT EXISTS idx_orders_created
    ON orders(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_orders_payment_status
    ON orders(payment_status);

CREATE INDEX IF NOT EXISTS idx_orders_fulfilment_status
    ON orders(fulfilment_status);

CREATE INDEX IF NOT EXISTS idx_order_items_order
    ON order_items(order_id);

CREATE INDEX IF NOT EXISTS idx_order_items_vendor
    ON order_items(vendor_id);

CREATE INDEX IF NOT EXISTS idx_referrals_reseller
    ON referrals(reseller_id);

CREATE INDEX IF NOT EXISTS idx_referral_codes_reseller_active
    ON referral_codes(reseller_id, is_active);

CREATE INDEX IF NOT EXISTS idx_referral_clicks_code_created
    ON referral_clicks(referral_code, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_order_referrals_reseller
    ON order_referrals(reseller_id);

CREATE INDEX IF NOT EXISTS idx_reseller_commissions_reseller_status
    ON reseller_commissions(reseller_id, status);

CREATE INDEX IF NOT EXISTS idx_sessions_user_expiry
    ON sessions(user_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created
    ON audit_logs(actor_id, created_at DESC);
