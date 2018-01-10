package htlcswitch

type Operator interface {
}

/*
type OperatorStore interface {
	LockInHtlcs(*bolt.Tx, ...channeldb.LogUpdate) error
	ProcesLockedInHtlcs(*bolt.Tx, ...uint64) error
	AckLockedInHtlcs(*bolt.Tx, ...channeldb.LogUpdate) error
	AckLockedInHtlcIndexes(*bolt.Tx, ...uint64) error
}
*/
