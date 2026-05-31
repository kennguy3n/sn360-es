package postgres

import (
	"context"
	"database/sql/driver"
	"errors"
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
