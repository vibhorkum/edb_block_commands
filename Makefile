MODULES = edb_block_commands
PGFILEDESC = "edb_block_commands - block utility and DML commands"

EXTENSION = edb_block_commands
DATA = edb_block_commands--1.0.sql

LDFLAGS_SL += $(filter -lm, $(LIBS))

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
