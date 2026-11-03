/**
 * Repository layer for Node.js Deep Taint Analysis
 */

const mockDb = {
    query: (sql, params) => Promise.resolve([])
};

class OrderRepository {
    async executeRawSql(filter) {
        // GT: id=TAINT-NODE-001 type=TP cwe=CWE-89 rule=deep-taint-sqli
        return mockDb.query("SELECT * FROM orders WHERE status = '" + filter + "'");
    }

    async executeParameterized(orderId) {
        // GT: id=TAINT-NODE-011 type=FP reason=multi-hop-parameterized-query
        return mockDb.query("SELECT * FROM orders WHERE id = $1", [orderId]);
    }

    async executeSecondOrder(cachedTag) {
        // GT: id=TAINT-NODE-005 type=TP cwe=CWE-89 rule=second-order-sqli
        return mockDb.query("SELECT summary FROM audit_trail WHERE tag = '" + cachedTag + "'");
    }

    async executeConstantQuery(_unused) {
        // GT: id=TAINT-NODE-019 type=FP reason=constant-query-sink
        return mockDb.query("SELECT 1 FROM status_catalog LIMIT 1");
    }

    async updateAccountBalance(targetId, amount) {
        // GT: id=TAINT-NODE-010 type=TP cwe=CWE-639 rule=idor-unauthorized-update
        return mockDb.query("UPDATE accounts SET balance = balance + $1 WHERE id = $2", [amount, targetId]);
    }
}

module.exports = { OrderRepository };

