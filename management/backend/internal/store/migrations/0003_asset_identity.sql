-- Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- The assets registry keyed on (tenant_id, asset_id), but asset_id defaults to
-- the empty string and not every event carries one. Every asset reported with
-- a name but no id therefore collapsed onto the single row (tenant_id, ''),
-- where the name flipped to whichever event arrived last and event_count
-- accumulated totals from unrelated assets.
--
-- The ingest writer already groups by (tenant, asset_id, asset_name), so the
-- storage key is widened to match its grouping key.

-- Drop the conflated rows outright rather than trying to split them. Under
-- the old key every id-less asset shared the single row (tenant_id, ''), whose
-- asset_name is whichever event arrived last and whose event_count is a sum
-- over unrelated assets; there is nothing in the row to attribute those counts
-- back from. Ingest rediscovers each asset on its next event, so the registry
-- refills with correct per-asset rows instead of carrying a wrong total
-- forward.
DELETE FROM assets WHERE asset_id = '';

-- The new index is created before the old constraint is dropped, so an
-- instance still running the previous build keeps a constraint that matches
-- its ON CONFLICT target for as long as possible during an upgrade. No
-- deduplication is needed first: the old key was unique on (tenant_id,
-- asset_id), a prefix of the new one, so no two rows can collide on it.
--
-- Not CONCURRENTLY: Migrate runs each migration inside a transaction, and
-- CREATE INDEX CONCURRENTLY cannot run in one. The table is small — one row
-- per discovered asset — so the brief lock is not worth splitting the
-- migration's atomicity for.
CREATE UNIQUE INDEX IF NOT EXISTS assets_identity_key
    ON assets (tenant_id, asset_id, asset_name);

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_tenant_id_asset_id_key;
