-- CREATE INDEX ix_txin_previous_output_transaction_hash_null_txout_id ON txin (previous_output_transaction_hash) WHERE txout_id IS null;
-- CREATE INDEX ix_block_prev_block_hash_null_prev_block_id ON block (prev_block_hash) WHERE prev_block_id IS NULL;

-- UPDATE block SET block.prev_block_id = prev_block.id
-- FROM block prev_block
-- WHERE prev_block.block_hash = block.prev_block_hash;


CREATE OR REPLACE VIEW address_balance_view AS
SELECT txout.to_address address, SUM(value) balance
FROM txout
-- JOIN transaction t ON txout.transaction_id = t.id
-- LEFT JOIN txin ON txout.transaction_index = txin.previous_output_index AND t.tx_hash = txin.previous_output_transaction_hash
LEFT JOIN txin ON txout.id = txin.txout_id
WHERE txin.id IS NULL
GROUP BY txout.to_address;

-- CREATE TABLE address_balance AS SELECT * FROM address_balance_view;
-- CREATE UNIQUE INDEX address_balance_address_idx ON address_balance (address);
ALTER TABLE address_balance OWNER TO pybitcoin;

-- UPDATE address_balance SET address_balance.balance = v.balance FROM address_balance_view v WHERE address_balance.address = v.address;

CREATE OR REPLACE FUNCTION public.address_balance_refresh_row(in_address character varying(34))
  RETURNS void AS
  $$
    BEGIN
      DELETE FROM public.address_balance WHERE address = in_address;
      INSERT INTO public.address_balance SELECT * FROM public.address_balance_view WHERE address = in_address;
    END;
  $$
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  COST 100;
ALTER FUNCTION public.address_balance_refresh_row(character varying(34))
  OWNER TO pybitcoin;

-- CREATE OR REPLACE FUNCTION public.address_balance_txout_insert()
--   RETURNS trigger AS
-- ' BEGIN PERFORM public.address_balance_refresh_row(NEW.to_address); RETURN NULL; END; '
--   LANGUAGE plpgsql VOLATILE SECURITY DEFINER
--   COST 100;
-- ALTER FUNCTION public.address_balance_txout_insert()
--   OWNER TO pybitcoin;
--
-- CREATE TRIGGER address_balance_txout_insert_trigger
--   AFTER INSERT
--   ON public.txout
--   FOR EACH ROW
--   EXECUTE PROCEDURE public.address_balance_txout_insert();


CREATE OR REPLACE FUNCTION public.address_balance_refresh_row_txin_id(in_id integer)
  RETURNS void AS
  $$
    DECLARE
      prev_address character varying(34);
      l_txout_id integer;
    BEGIN
      SELECT txout_id INTO l_txout_id FROM txin WHERE id = in_id;
      IF l_txout_id IS NOT NULL THEN
        SELECT to_address INTO prev_address FROM public.txout WHERE id = l_txout_id;
        PERFORM public.address_balance_refresh_row(prev_address);
      END IF;
    END;
  $$
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  COST 100;
ALTER FUNCTION public.address_balance_refresh_row_txin_id(integer)
  OWNER TO pybitcoin;

-- CREATE OR REPLACE FUNCTION public.address_balance_refresh_row_txin_id(in_id integer)
--   RETURNS void AS
--   $$
--     DECLARE
--       l_txout_id integer;
--     BEGIN
--       SELECT txout_id INTO l_txout_id
--         FROM public.txin
--         WHERE id = in_id;
--       PERFORM public.address_balance_refresh_row_txout_id(l_txout_id);
--     END;
--   $$
--   LANGUAGE plpgsql VOLATILE SECURITY DEFINER
--   COST 100;
-- ALTER FUNCTION public.address_balance_refresh_row_txin_id(integer)
--   OWNER TO pybitcoin;

-- CREATE OR REPLACE FUNCTION public.address_balance_refresh_row_txin(in_previous_output_tx_hash bytea, in_previous_output_index bigint)
--   RETURNS void AS '
--     DECLARE
--         prev_address character varying(34);
--     BEGIN
--         SELECT to_address INTO prev_address
--             FROM public.txout
--             WHERE transaction_id = (
--                 SELECT id FROM public.transaction WHERE tx_hash = in_previous_output_tx_hash
--             ) AND transaction_index = in_previous_output_index;
--         PERFORM public.address_balance_refresh_row(prev_address);
--     END;
-- ' LANGUAGE plpgsql VOLATILE SECURITY DEFINER
--   COST 100;
-- ALTER FUNCTION public.address_balance_refresh_row_txin(bytea, bigint)
--   OWNER TO pybitcoin;
--
--
-- CREATE OR REPLACE FUNCTION public.address_balance_txin_insert()
--   RETURNS trigger AS
-- ' BEGIN PERFORM public.address_balance_refresh_row_txin(NEW.previous_output_transaction_hash, NEW.previous_output_index); RETURN NULL; END; '
--   LANGUAGE plpgsql VOLATILE SECURITY DEFINER
--   COST 100;
-- ALTER FUNCTION public.address_balance_txin_insert()
--   OWNER TO pybitcoin;
--
--
-- CREATE TRIGGER address_balance_txin_insert_trigger
--   AFTER INSERT
--   ON public.txin
--   FOR EACH ROW
--   EXECUTE PROCEDURE public.address_balance_txin_insert();




CREATE OR REPLACE FUNCTION public.update_txin_txout_id_by_txin_id(in_id integer)
  RETURNS void AS
  $$
    BEGIN
      UPDATE txin SET txout_id = txout.id
      FROM txout JOIN transaction t ON txout.transaction_id = t.id
      WHERE txout_id IS NULL
      AND t.tx_hash = txin.previous_output_transaction_hash
      AND txout.transaction_index = txin.previous_output_index
      AND txin.id = in_id;
    END;
  $$
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  COST 100;
ALTER FUNCTION public.update_txin_txout_id_by_txin_id(integer)
  OWNER TO pybitcoin;


CREATE OR REPLACE FUNCTION public.on_txin_insert()
  RETURNS trigger AS
  $$
    BEGIN
      PERFORM public.update_txin_txout_id_by_txin_id(NEW.id);
      PERFORM public.address_balance_refresh_row_txin_id(NEW.id);
      RETURN NULL;
    END;
  $$
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  COST 100;
ALTER FUNCTION public.on_txin_insert()
  OWNER TO pybitcoin;


CREATE TRIGGER txin_insert_trigger
  AFTER INSERT
  ON public.txin
  FOR EACH ROW
  EXECUTE PROCEDURE public.on_txin_insert();

ALTER TABLE public.txin ENABLE TRIGGER txin_insert_trigger;



-- Not needed if we're only adding new blocks/transactions
CREATE OR REPLACE FUNCTION public.update_txin_txout_id_by_txout_id_tx_id(in_txout_id integer, in_txout_index integer, in_transaction_id integer)
  RETURNS void AS
  $$
    BEGIN
      UPDATE txin SET txout_id = in_txout_id
      WHERE txout_id IS NULL
      AND previous_output_transaction_hash = (SELECT tx_hash FROM transaction WHERE id = in_transaction_id)
      AND previous_output_index = in_txout_index;
    END;
  $$
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  COST 100;
ALTER FUNCTION public.update_txin_txout_id_by_txout_id_tx_id(integer, integer, integer)
  OWNER TO pybitcoin;


CREATE OR REPLACE FUNCTION public.on_txout_insert()
  RETURNS trigger AS
  $$
    BEGIN
      -- Not needed if we're only adding new blocks/transactions
      PERFORM public.update_txin_txout_id_by_txout_id_tx_id(NEW.id, NEW.transaction_index, NEW.transaction_id);
      -- If the above function finds a match, technically we don't
      -- need to do this as the potential new balance has already been spent
      PERFORM public.address_balance_refresh_row(NEW.to_address);
      RETURN NULL;
    END;
  $$
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  COST 100;
ALTER FUNCTION public.on_txout_insert()
  OWNER TO pybitcoin;


CREATE TRIGGER txout_insert_trigger
  AFTER INSERT
  ON public.txout
  FOR EACH ROW
  EXECUTE PROCEDURE public.on_txout_insert();

ALTER TABLE public.txout ENABLE TRIGGER txout_insert_trigger;










-- -- Function: stats.leaderboard_stats_delete()
-- -- DROP FUNCTION stats.leaderboard_stats_delete();
-- CREATE OR REPLACE FUNCTION stats.leaderboard_stats_delete()
--   RETURNS trigger AS
-- ' BEGIN PERFORM stats.leaderboard_refresh_row(OLD.stattype, OLD.actortype, OLD.ownerid); RETURN NULL; END; '
--   LANGUAGE plpgsql VOLATILE SECURITY DEFINER
--   COST 100;
-- ALTER FUNCTION stats.leaderboard_stats_delete()
--   OWNER TO postgres;
--
-- -- Trigger: leaderboard_stats_delete_trigger on stats.stats
-- -- DROP TRIGGER leaderboard_stats_delete_trigger ON stats.stats;
-- CREATE TRIGGER leaderboard_stats_delete_trigger
--   AFTER DELETE
--   ON stats.stats
--   FOR EACH ROW
--   EXECUTE PROCEDURE stats.leaderboard_stats_delete();
--
--
-- -- Function: stats.leaderboard_stats_update()
-- -- DROP FUNCTION stats.leaderboard_stats_update();
-- CREATE OR REPLACE FUNCTION stats.leaderboard_stats_update()
--   RETURNS trigger AS
-- ' BEGIN PERFORM stats.leaderboard_refresh_row(OLD.stattype, OLD.actortype, OLD.ownerid); IF OLD.stattype <> NEW.stattype OR OLD.actortype <> NEW.actortype OR OLD.ownerid <> NEW.ownerid THEN PERFORM stats.leaderboard_refresh_row(NEW.stattype, NEW.actortype, NEW.ownerid); END IF; RETURN NULL; END; '
--   LANGUAGE plpgsql VOLATILE SECURITY DEFINER
--   COST 100;
-- ALTER FUNCTION stats.leaderboard_stats_update()
--   OWNER TO postgres;
--
--
-- -- Trigger: leaderboard_stats_update_trigger on stats.stats
-- -- DROP TRIGGER leaderboard_stats_update_trigger ON stats.stats;
-- CREATE TRIGGER leaderboard_stats_update_trigger
--   AFTER UPDATE
--   ON stats.stats
--   FOR EACH ROW
--   EXECUTE PROCEDURE stats.leaderboard_stats_update();
