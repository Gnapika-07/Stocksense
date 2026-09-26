-- =====================================================================
--  STOCKSENSE — Inventory Management System
--  Database Schema (PostgreSQL 13+)
--  Odoo Hackathon Submission
-- =====================================================================
--  Design notes
--  - Every stock-moving document (Receipt / Delivery / Internal Transfer)
--    follows the same lifecycle: Draft -> Waiting -> Ready -> Done/Canceled.
--    Stock only changes on the transition INTO 'Done' (i.e. on "Validate").
--  - stock_ledger is the single source of truth for "what happened to the
--    stock and when" -> powers the Move History screen.
--  - stock_levels is a materialized per (product, warehouse) balance so
--    dashboard KPIs and low-stock alerts are cheap to query.
--  - Everything is wrapped so the API layer can run each validate/adjust
--    action inside one transaction with SELECT ... FOR UPDATE, keeping
--    concurrent picks/receipts from double-counting stock.
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid(), crypt() helpers
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive email column
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- fuzzy SKU / name search

-- ---------------------------------------------------------------------
-- Enumerations
-- ---------------------------------------------------------------------
CREATE TYPE document_status AS ENUM ('Draft', 'Waiting', 'Ready', 'Done', 'Canceled');
CREATE TYPE user_role        AS ENUM ('Inventory Manager', 'Warehouse Staff', 'Admin');
CREATE TYPE movement_type    AS ENUM ('Receipt', 'Delivery', 'Transfer', 'Adjustment');

-- ---------------------------------------------------------------------
-- Users & Authentication
-- ---------------------------------------------------------------------
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(120)        NOT NULL,
    email           CITEXT              NOT NULL UNIQUE,
    password_hash   VARCHAR(255)        NOT NULL,
    role            user_role           NOT NULL DEFAULT 'Inventory Manager',
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT now()
);
CREATE TABLE password_reset_otps (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_code        CHAR(4)      NOT NULL,
    expires_at      TIMESTAMPTZ  NOT NULL,
    consumed        BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_otp_user_active ON password_reset_otps(user_id) WHERE consumed = FALSE;

-- ---------------------------------------------------------------------
-- Warehouses / Locations
-- ---------------------------------------------------------------------
CREATE TABLE warehouses (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100) NOT NULL UNIQUE,
    code            VARCHAR(20)  UNIQUE,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Product catalog
-- ---------------------------------------------------------------------
CREATE TABLE product_categories (
    id      SERIAL PRIMARY KEY,
    name    VARCHAR(80) NOT NULL UNIQUE
);

CREATE TABLE products (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(150) NOT NULL,
    sku             VARCHAR(40)  NOT NULL UNIQUE,
    category_id     INTEGER      REFERENCES product_categories(id) ON DELETE SET NULL,
    uom             VARCHAR(20)  NOT NULL DEFAULT 'pcs',   -- kg, pcs, roll, box...
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_products_sku_search  ON products USING gin (sku gin_trgm_ops);
CREATE INDEX idx_products_name_search ON products USING gin (name gin_trgm_ops);

-- Reordering rules — "Products > Reordering rules" in the spec
CREATE TABLE reorder_rules (
    id              SERIAL PRIMARY KEY,
    product_id      INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    warehouse_id    INTEGER NOT NULL REFERENCES warehouses(id) ON DELETE CASCADE,
    min_qty         NUMERIC(14,3) NOT NULL DEFAULT 0,   -- reorder point
    max_qty         NUMERIC(14,3),                       -- target stock level
    UNIQUE (product_id, warehouse_id)
);

-- Materialized stock balance per product per warehouse
CREATE TABLE stock_levels (
    product_id      INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    warehouse_id    INTEGER NOT NULL REFERENCES warehouses(id) ON DELETE CASCADE,
    quantity        NUMERIC(14,3) NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, warehouse_id)
);

-- ---------------------------------------------------------------------
-- Receipts (Incoming stock)
-- ---------------------------------------------------------------------
CREATE TABLE receipts (
    id              SERIAL PRIMARY KEY,
    reference       VARCHAR(30)  NOT NULL UNIQUE,        -- REC-0001
    supplier        VARCHAR(150) NOT NULL,
    warehouse_id    INTEGER      NOT NULL REFERENCES warehouses(id),
    status          document_status NOT NULL DEFAULT 'Draft',
    created_by      INTEGER      REFERENCES users(id),
    scheduled_date  DATE         NOT NULL DEFAULT CURRENT_DATE,
    validated_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE receipt_lines (
    id              SERIAL PRIMARY KEY,
    receipt_id      INTEGER NOT NULL REFERENCES receipts(id) ON DELETE CASCADE,
    product_id      INTEGER NOT NULL REFERENCES products(id),
    quantity        NUMERIC(14,3) NOT NULL CHECK (quantity > 0)
);

-- ---------------------------------------------------------------------
-- Delivery Orders (Outgoing stock)
-- ---------------------------------------------------------------------
CREATE TABLE deliveries (
    id              SERIAL PRIMARY KEY,
    reference       VARCHAR(30)  NOT NULL UNIQUE,        -- DO-0001
    customer        VARCHAR(150) NOT NULL,
    warehouse_id    INTEGER      NOT NULL REFERENCES warehouses(id),
    status          document_status NOT NULL DEFAULT 'Draft',
    created_by      INTEGER      REFERENCES users(id),
    scheduled_date  DATE         NOT NULL DEFAULT CURRENT_DATE,
    validated_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE delivery_lines (
    id              SERIAL PRIMARY KEY,
    delivery_id     INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
    product_id      INTEGER NOT NULL REFERENCES products(id),
    quantity        NUMERIC(14,3) NOT NULL CHECK (quantity > 0)
);

-- ---------------------------------------------------------------------
-- Internal Transfers (stock moves between warehouses/racks)
-- ---------------------------------------------------------------------
CREATE TABLE transfers (
    id                  SERIAL PRIMARY KEY,
    reference           VARCHAR(30) NOT NULL UNIQUE,     -- INT-0001
    from_warehouse_id   INTEGER NOT NULL REFERENCES warehouses(id),
    to_warehouse_id     INTEGER NOT NULL REFERENCES warehouses(id),
    status              document_status NOT NULL DEFAULT 'Draft',
    created_by          INTEGER REFERENCES users(id),
    scheduled_date      DATE NOT NULL DEFAULT CURRENT_DATE,
    validated_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_warehouse_id <> to_warehouse_id)
);

CREATE TABLE transfer_lines (
    id              SERIAL PRIMARY KEY,
    transfer_id     INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    product_id      INTEGER NOT NULL REFERENCES products(id),
    quantity        NUMERIC(14,3) NOT NULL CHECK (quantity > 0)
);

-- ---------------------------------------------------------------------
-- Stock Adjustments (recorded vs physical count)
-- ---------------------------------------------------------------------
CREATE TABLE adjustments (
    id              SERIAL PRIMARY KEY,
    product_id      INTEGER NOT NULL REFERENCES products(id),
    warehouse_id    INTEGER NOT NULL REFERENCES warehouses(id),
    before_qty      NUMERIC(14,3) NOT NULL,
    counted_qty     NUMERIC(14,3) NOT NULL,
    diff_qty        NUMERIC(14,3) GENERATED ALWAYS AS (counted_qty - before_qty) STORED,
    reason          VARCHAR(200),
    created_by      INTEGER REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Stock Ledger — immutable audit trail, powers "Move History"
-- ---------------------------------------------------------------------
CREATE TABLE stock_ledger (
    id              BIGSERIAL PRIMARY KEY,
    movement_type   movement_type NOT NULL,
    product_id      INTEGER NOT NULL REFERENCES products(id),
    warehouse_id    INTEGER REFERENCES warehouses(id),        -- NULL for cross-warehouse summary rows
    quantity_change NUMERIC(14,3) NOT NULL,                    -- signed: +in / -out
    reference       VARCHAR(30) NOT NULL,                      -- REC-0001 / DO-0001 / INT-0001 / ADJ-0001
    description     TEXT NOT NULL,
    created_by      INTEGER REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ledger_created_at ON stock_ledger (created_at DESC);
CREATE INDEX idx_ledger_product    ON stock_ledger (product_id);

-- ---------------------------------------------------------------------
-- Sequences for human-readable references (REC-0001, DO-0001, INT-0001)
-- ---------------------------------------------------------------------
CREATE SEQUENCE receipt_ref_seq   START 1;
CREATE SEQUENCE delivery_ref_seq  START 1;
CREATE SEQUENCE transfer_ref_seq  START 1;
CREATE SEQUENCE adjustment_ref_seq START 1;

-- ---------------------------------------------------------------------
-- Trigger: keep updated_at fresh on products / users
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_products_touch BEFORE UPDATE ON products
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER trg_users_touch BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------------
-- Views used directly by the Dashboard KPIs
-- ---------------------------------------------------------------------
CREATE VIEW v_product_total_stock AS
SELECT p.id AS product_id, p.name, p.sku, p.uom,
       COALESCE(SUM(sl.quantity), 0) AS total_stock
FROM products p
LEFT JOIN stock_levels sl ON sl.product_id = p.id
GROUP BY p.id, p.name, p.sku, p.uom;

CREATE VIEW v_low_stock AS
SELECT v.*, COALESCE(MIN(r.min_qty), 15) AS threshold
FROM v_product_total_stock v
LEFT JOIN reorder_rules r ON r.product_id = v.product_id
GROUP BY v.product_id, v.name, v.sku, v.uom, v.total_stock
HAVING v.total_stock <= COALESCE(MIN(r.min_qty), 15);

CREATE VIEW v_dashboard_kpis AS
SELECT
  (SELECT COUNT(*) FROM products WHERE is_active) AS total_products,
  (SELECT COUNT(*) FROM v_low_stock)               AS low_stock_items,
  (SELECT COUNT(*) FROM receipts   WHERE status IN ('Draft','Waiting','Ready'))  AS pending_receipts,
  (SELECT COUNT(*) FROM deliveries WHERE status IN ('Draft','Waiting','Ready'))  AS pending_deliveries,
  (SELECT COUNT(*) FROM transfers  WHERE status IN ('Draft','Waiting','Ready'))  AS transfers_scheduled;

COMMIT;

-- =====================================================================
--  SEED DATA — mirrors the frontend's demo state so both line up 1:1
-- =====================================================================
BEGIN;

INSERT INTO warehouses (name, code) VALUES
  ('Main Warehouse',   'WH-MAIN'),
  ('Warehouse 2',      'WH-002'),
  ('Production Floor', 'WH-PROD');

INSERT INTO product_categories (name) VALUES
  ('Raw Material'), ('Furniture'), ('Consumable');

INSERT INTO users (name, email, password_hash, role) VALUES
  ('Priya Rao', 'priya@stocksense.io', crypt('Passw0rd!', gen_salt('bf')), 'Inventory Manager');

INSERT INTO products (name, sku, category_id, uom) VALUES
  ('Steel Rods',    'STL-001', (SELECT id FROM product_categories WHERE name='Raw Material'), 'kg'),
  ('Office Chairs', 'CHR-010', (SELECT id FROM product_categories WHERE name='Furniture'),     'pcs'),
  ('Packing Tape',  'PKG-004', (SELECT id FROM product_categories WHERE name='Consumable'),    'roll');

INSERT INTO reorder_rules (product_id, warehouse_id, min_qty, max_qty)
SELECT p.id, w.id, 15, 200 FROM products p, warehouses w WHERE w.name = 'Main Warehouse';

INSERT INTO stock_levels (product_id, warehouse_id, quantity) VALUES
  ((SELECT id FROM products WHERE sku='STL-001'), (SELECT id FROM warehouses WHERE name='Main Warehouse'), 150),
  ((SELECT id FROM products WHERE sku='CHR-010'), (SELECT id FROM warehouses WHERE name='Main Warehouse'), 32),
  ((SELECT id FROM products WHERE sku='PKG-004'), (SELECT id FROM warehouses WHERE name='Main Warehouse'), 8);

INSERT INTO receipts (reference, supplier, warehouse_id, status, scheduled_date, validated_at)
VALUES ('REC-0001', 'Acme Metals', (SELECT id FROM warehouses WHERE name='Main Warehouse'), 'Done', '2026-09-20', '2026-09-20 10:00:00');
INSERT INTO receipt_lines (receipt_id, product_id, quantity)
VALUES (currval('receipts_id_seq'), (SELECT id FROM products WHERE sku='STL-001'), 50);
SELECT setval('receipt_ref_seq', 1);

INSERT INTO deliveries (reference, customer, warehouse_id, status, scheduled_date)
VALUES ('DO-0001', 'BuildCo', (SELECT id FROM warehouses WHERE name='Main Warehouse'), 'Waiting', '2026-09-22');
INSERT INTO delivery_lines (delivery_id, product_id, quantity)
VALUES (currval('deliveries_id_seq'), (SELECT id FROM products WHERE sku='CHR-010'), 10);
SELECT setval('delivery_ref_seq', 1);

INSERT INTO transfers (reference, from_warehouse_id, to_warehouse_id, status, scheduled_date, validated_at)
VALUES ('INT-0001', (SELECT id FROM warehouses WHERE name='Main Warehouse'),
                     (SELECT id FROM warehouses WHERE name='Production Floor'), 'Done', '2026-09-18', '2026-09-18 09:00:00');
INSERT INTO transfer_lines (transfer_id, product_id, quantity)
VALUES (currval('transfers_id_seq'), (SELECT id FROM products WHERE sku='STL-001'), 20);
SELECT setval('transfer_ref_seq', 1);

INSERT INTO stock_ledger (movement_type, product_id, warehouse_id, quantity_change, reference, description)
VALUES
 ('Receipt',  (SELECT id FROM products WHERE sku='STL-001'), (SELECT id FROM warehouses WHERE name='Main Warehouse'),  50, 'REC-0001', '+50 kg Steel Rods into Main Warehouse (REC-0001)'),
 ('Transfer', (SELECT id FROM products WHERE sku='STL-001'), (SELECT id FROM warehouses WHERE name='Main Warehouse'), -20, 'INT-0001', '-20 kg Steel Rods: Main Warehouse -> Production Floor (INT-0001)'),
 ('Transfer', (SELECT id FROM products WHERE sku='STL-001'), (SELECT id FROM warehouses WHERE name='Production Floor'), 20, 'INT-0001', '+20 kg Steel Rods: Main Warehouse -> Production Floor (INT-0001)');

COMMIT;

-- End of schema + seed data.
