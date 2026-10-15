-- ZAVO Marketplace Complete Database Schema
-- Database Name: zavo-stores-db

-- 1. Users and Roles
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer', -- admin, vendor, reseller, customer
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Vendors / Suppliers
CREATE TABLE IF NOT EXISTS vendors (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    shop_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, rejected, suspended
    documents_url TEXT,
    contact_phone TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 3. Products
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    vendor_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'draft', -- draft, pending, active, archived
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES vendors(id)
);

-- 4. Orders
CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    customer_email TEXT NOT NULL,
    customer_phone TEXT,
    shipping_address TEXT,
    total_amount REAL NOT NULL,
    payment_status TEXT NOT NULL DEFAULT 'pending_payment', -- pending_payment, paid, failed, refunded
    fulfilment_status TEXT NOT NULL DEFAULT 'pending', -- pending, processing, shipped, delivered, cancelled
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 5. Order Items
CREATE TABLE IF NOT EXISTS order_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (vendor_id) REFERENCES vendors(id)
);

-- 6. Reseller Referral Links
CREATE TABLE IF NOT EXISTS referrals (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    referral_code TEXT UNIQUE NOT NULL,
    clicks INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- 7. Commissions Ledger
CREATE TABLE IF NOT EXISTS commissions (
    id TEXT PRIMARY KEY,
    reseller_id TEXT NOT NULL,
    order_id TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, payable, paid, reversed
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES users(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

-- 8. Security & Admin Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
