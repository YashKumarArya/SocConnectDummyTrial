-- DROP EDR objects (view + table) in the soc database
-- CAUTION: this will permanently remove data. Run only if you intend to delete the table and view.

DROP VIEW IF EXISTS soc.edr_alerts_summary;
DROP TABLE IF EXISTS soc.edr_alerts_ocsf;
