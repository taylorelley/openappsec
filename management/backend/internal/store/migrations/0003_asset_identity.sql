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

-- Collapse any rows that the old key had already merged, keeping the newest
-- name and the summed count, so the wider unique index can be created.
DELETE FROM assets a
      USING assets b
      WHERE a.tenant_id = b.tenant_id
        AND a.asset_id = b.asset_id
        AND a.asset_name = b.asset_name
        AND a.ctid < b.ctid;

-- The new index is created before the old constraint is dropped, so an
-- instance still running the previous build keeps a constraint that matches
-- its ON CONFLICT target for as long as possible during an upgrade.
CREATE UNIQUE INDEX IF NOT EXISTS assets_identity_key
    ON assets (tenant_id, asset_id, asset_name);

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_tenant_id_asset_id_key;
