// Proof of concept only. Values are public samples, not live credentials.
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const db = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/main";

app.get("/api/v1/admin/users", handler);
