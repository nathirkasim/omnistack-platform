package main

import (
	"database/sql"
	"fmt"
)

type OrderRepository struct {
	db *sql.DB
}

func (r *OrderRepository) ExecuteRawSQL(filter string) error {
	// GT: id=TAINT-GO-001 type=TP cwe=CWE-89 rule=deep-taint-sqli
	_, err := r.db.Query(fmt.Sprintf("SELECT id FROM orders WHERE status = '%s'", filter))
	return err
}

func (r *OrderRepository) ExecuteParameterized(orderID string) error {
	// GT: id=TAINT-GO-011 type=FP reason=multi-hop-parameterized-query
	_, err := r.db.Query("SELECT id FROM orders WHERE id = ?", orderID)
	return err
}

func (r *OrderRepository) ExecuteSecondOrder(cachedTag string) error {
	// GT: id=TAINT-GO-005 type=TP cwe=CWE-89 rule=second-order-sqli
	_, err := r.db.Query(fmt.Sprintf("SELECT record FROM audit_trail WHERE tag = '%s'", cachedTag))
	return err
}

func (r *OrderRepository) ExecuteConstantQuery(_unused string) error {
	// GT: id=TAINT-GO-019 type=FP reason=constant-query-sink
	_, err := r.db.Query("SELECT 'constant-value'")
	return err
}

func (r *OrderRepository) UpdateAccountBalance(targetID string, amount float64) error {
	// GT: id=TAINT-GO-010 type=TP cwe=CWE-639 rule=idor-unauthorized-update
	_, err := r.db.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, targetID)
	return err
}
