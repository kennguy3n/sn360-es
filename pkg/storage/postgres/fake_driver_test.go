package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
)

// fakeConnector is a minimal database/sql/driver.Connector whose
// Connect always returns a fakeConn. We use it from the unit tests in
// tenant_context_test.go to construct a *sql.DB / *sql.Conn that we
// can pass through context plumbing WITHOUT actually dialling a real
// database. The conn itself errors on every query — the unit tests
// only need identity-equal sentinels, not working queries.
type fakeConnector struct{}

func (fakeConnector) Connect(context.Context) (driver.Conn, error) { return fakeConn{}, nil }
func (fakeConnector) Driver() driver.Driver                        { return fakeDriver{} }

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return fakeConn{}, nil }

// fakeConn implements driver.Conn well enough to be acquired via
// sql.DB.Conn() but rejects every prepared / exec / query. Integration
// behaviour lives in postgres_integration_test.go behind the
// `integration` build tag and uses real Postgres via testcontainers.
type fakeConn struct{}

func (fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("postgres: fakeConn does not implement Prepare; use the integration build tag for real queries")
}
func (fakeConn) Close() error { return nil }
func (fakeConn) Begin() (driver.Tx, error) {
	return nil, errors.New("postgres: fakeConn does not implement Begin")
}

// taggedConnector is the same idea as fakeConnector, but every
// operation produced by the *sql.DB it backs returns an error
// whose text embeds the tag. Tests use it to distinguish which of
// several *sql.DBs a Query / Exec / Begin call actually hit
// (e.g. the WS-2a read-replica routing tests in
// read_replica_test.go need to assert that QueryContext lands on
// the read pool, not the write pool, when both are wired).
type taggedConnector struct{ tag string }

func (c taggedConnector) Connect(context.Context) (driver.Conn, error) {
	return taggedConn(c), nil
}
func (taggedConnector) Driver() driver.Driver { return taggedDriver{} }

type taggedDriver struct{}

func (taggedDriver) Open(string) (driver.Conn, error) {
	return taggedConn{tag: "unrouted"}, nil
}

type taggedConn struct{ tag string }

func (c taggedConn) Prepare(string) (driver.Stmt, error) { return nil, errFromTag(c.tag) }
func (taggedConn) Close() error                          { return nil }
func (c taggedConn) Begin() (driver.Tx, error)           { return nil, errFromTag(c.tag) }

// taggedError is the sentinel returned by every taggedConn op so
// tests can use errors.Is(err, errFromTag("writer")) to assert
// the routing path without depending on the exact stringification
// of the wrapped database/sql error.
type taggedError struct{ tag string }

func (e taggedError) Error() string {
	return fmt.Sprintf("postgres: taggedConn(%s) op rejected", e.tag)
}
func (e taggedError) Is(other error) bool {
	o, ok := other.(taggedError)
	return ok && o.tag == e.tag
}

func errFromTag(tag string) error { return taggedError{tag: tag} }
