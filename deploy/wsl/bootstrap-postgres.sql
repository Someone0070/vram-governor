-- Local WSL development authority. Peer authentication keeps credentials out
-- of config files: the controller process runs as Linux user `vram-governor` and maps
-- to the matching PostgreSQL role over the local Unix socket.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vram-governor') THEN
    CREATE ROLE "vram-governor" LOGIN;
  END IF;
END
$$;

SELECT 'CREATE DATABASE vram_governor OWNER "vram-governor"'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'vram_governor')
\gexec

ALTER DATABASE vram_governor OWNER TO "vram-governor";
