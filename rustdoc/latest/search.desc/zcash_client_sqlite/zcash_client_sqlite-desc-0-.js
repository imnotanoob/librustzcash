searchState.loadedDescShard("zcash_client_sqlite", 0, "<em>An SQLite-based Zcash light client.</em>\nThe ID type for accounts.\nA handle for the SQLite block source.\nA block source that reads block data from disk and block …\nErrors that can be generated by the …\nAn opaque type for received note identifiers.\nA wrapper for a SQLite transaction affecting the wallet …\nA newtype wrapper for sqlite primary key values for the …\nA wrapper for the SQLite connection to the wallet database.\nUnwraps a raw <code>accounts</code> table primary key value from its …\nFunctions for enforcing chain validity and handling chain …\nError types for problems that may arise when reading or …\nReturns the metadata for the block with the given height, …\nConstruct a connection to the wallet database stored at …\nOpens a connection to the wallet database stored at the …\nCreates a filesystem-backed block store at the given path.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs an <code>AccountId</code> from a bare <code>u32</code> value. The …\nReturns metadata for the spendable notes in the wallet.\nReturns the maximum height of blocks known to the block …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nRewinds the BlockMeta Db to the <code>block_height</code> provided.\nFunctions for querying information in the wallet database.\nAdds a set of block metadata entries to the metadata …\nData structure representing a row in the block metadata …\nReturns the argument unchanged.\nFunctions for initializing the various databases.\nCalls <code>U::from(self)</code>.\nSets up the internal structure of the metadata cache …\nSets up the internal structure of the cache database.\nThe migration that added the <code>compactblocks_meta</code> table.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe account being added collides with an existing account …\nA caller attempted to initialize the accounts table with a …\nA caller attempted to construct a new account with an …\nThe account for which information was requested does not …\nAn error occurred in generating a Zcash address.\nThe address associated with a record being inserted was …\nAn error occurred while processing an account due to a …\nAn error occurred in computing wallet balance\nAn attempt to update block data would overwrite the …\nThe block at the specified height was not available from …\nThe height of the chain was not available; a call to …\nAn error occurred in inserting data into or accessing data …\nDecoding of a stored value from its serialized form has …\nWrapper for rusqlite errors.\nA Zcash key or address decoding error\nAn ephemeral address would be reused. The parameters are …\nA received memo cannot be interpreted as a UTF-8 string.\nThe rcm value for a note cannot be decoded to a valid …\nWrapper for errors from the IO subsystem\nAn error occurred deriving a spending key from a seed and …\nA range of blocks provided to the database as a unit was …\nA note selection query contained an invalid constant or …\nAn error occurred decoding a protobuf message.\nThe proposal cannot be constructed until transactions with …\nA requested rewind would violate invariants of the storage …\nThe primary error type for the SQLite wallet backend.\nIllegal attempt to reinitialize an already-initialized …\nAn error encountered in decoding a transparent address …\nAn error produced in legacy transparent address derivation\nThe account was imported, and ZIP-32 derivation …\nUnsupported pool type\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nAn account stored in a <code>zcash_client_sqlite</code> database.\nReturns the argument unchanged.\nFunctions for initializing the various databases.\nCalls <code>U::from(self)</code>.\nRaised when the caller attempts to add a checkpoint at a …\nErrors that can appear in SQLite-back <code>ShardStore</code> …\nErrors encountered querying stored shard data\nErrors in deserializing stored shard data\nRaised when attempting to add shard roots to the database …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAn error occurred in migrating a Zcash address or key.\nWrapper for amount balance violations\nReverting the specified migration is not supported.\nWrapper for commitment tree invariant violations\nDecoding of an existing value from its serialized form has …\nA feature required by the wallet database is not supported …\nWrapper for rusqlite errors.\nSome other unexpected violation of database business rules …\nA seed was provided that is not relevant to any of the …\nThe seed is required for the migration.\nReturns the argument unchanged.\nSets up the internal structure of the data database.\nCalls <code>U::from(self)</code>.")