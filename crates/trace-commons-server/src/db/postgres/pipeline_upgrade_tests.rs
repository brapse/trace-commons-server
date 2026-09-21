// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later
// INTEGRATION: upgrades a real V73 database and qualifies pipeline RLS.

use tokio_postgres::Client;
use uuid::Uuid;

use super::{MIGRATIONS, PgBackend, TRACE_COMMONS_RLS_TABLES, apply_and_record_migration};
use crate::{
    config::{DatabaseConfig, SslMode},
    db::Database,
};

fn database_config(url: String) -> DatabaseConfig {
    DatabaseConfig {
        url: url.into(),
        pool_size: 4,
        ssl_mode: SslMode::Prefer,
        login_resolver_url: None,
        gate_driver_url: None,
        pii_backstop_driver_url: None,
        invite_registry_url: None,
    }
}

fn isolated_upgrade_database_url() -> String {
    let url = std::env::var("TRACE_COMMONS_PIPELINE_PG_UPGRADE_TEST_URL")
        .expect("TRACE_COMMONS_PIPELINE_PG_UPGRADE_TEST_URL is required; no fallback is permitted");
    let target = url
        .parse::<tokio_postgres::Config>()
        .expect("parse explicit pipeline upgrade test URL");
    let hosts = target.get_hosts();
    let hosts_are_local = hosts.iter().all(|host| match host {
        tokio_postgres::config::Host::Tcp(host) => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(_) => true,
    });
    assert!(
        !hosts.is_empty() && hosts_are_local,
        "every explicit PostgreSQL host must be loopback or a local Unix socket"
    );
    assert!(
        target
            .get_hostaddrs()
            .iter()
            .all(std::net::IpAddr::is_loopback),
        "every PostgreSQL hostaddr override must be loopback"
    );
    assert!(
        target
            .get_dbname()
            .is_some_and(|name| name.starts_with("pipeline_test_")),
        "database name must start pipeline_test_"
    );
    url
}

async fn apply_real_migrations_through_v73(client: &mut Client) {
    client
        .batch_execute(
            "CREATE TABLE _trace_commons_migrations (\
                version INTEGER PRIMARY KEY,\
                name TEXT NOT NULL,\
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
            );",
        )
        .await
        .expect("create migration history table");
    for (version, name, sql) in MIGRATIONS.iter().filter(|(version, _, _)| *version <= 73) {
        apply_and_record_migration(client, *version, name, sql)
            .await
            .unwrap_or_else(|error| panic!("apply real V{version} ({name}): {error}"));
    }
}

async fn set_tenant(client: &Client, tenant: &str) {
    client
        .execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, false)",
            &[&tenant],
        )
        .await
        .expect("set migration test tenant");
}

#[tokio::test]
#[ignore = "requires PostgreSQL 16+ at isolated TRACE_COMMONS_PIPELINE_PG_UPGRADE_TEST_URL"]
async fn pipeline_v73_upgrade_installs_instrument_settlements_and_qualifies_rls() {
    let url = isolated_upgrade_database_url();
    let (mut admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect pipeline upgrade migration admin");
    tokio::spawn(async move { connection.await.expect("pipeline upgrade connection") });
    apply_real_migrations_through_v73(&mut admin).await;

    assert_eq!(
        admin
            .query_one("SELECT MAX(version) FROM _trace_commons_migrations", &[])
            .await
            .expect("read predecessor high-water mark")
            .get::<_, Option<i32>>(0),
        Some(73)
    );
    assert!(
        admin
            .query_one("SELECT to_regclass('public.pipeline_runs') IS NULL", &[],)
            .await
            .expect("inspect predecessor schema")
            .get::<_, bool>(0),
        "the V73 predecessor must not already contain pipeline storage"
    );

    let migrator = PgBackend::new(&database_config(url.clone()))
        .await
        .expect("connect current pipeline migrator");
    migrator
        .run_migrations()
        .await
        .expect("upgrade real V73 database through V80");

    let migration_rows: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM _trace_commons_migrations \
             WHERE version BETWEEN 74 AND 80",
            &[],
        )
        .await
        .expect("count pipeline migration records")
        .get(0);
    assert_eq!(migration_rows, 7, "V74 through V80 must all be recorded");

    let singleton_columns: i64 = admin
        .query_one(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'pipeline_runs' \
               AND column_name IN (\
                   'credit_event_id', 'credit_write_state',\
                   'settlement_batch_id', 'payout_state'\
               )",
            &[],
        )
        .await
        .expect("inspect pipeline run settlement columns")
        .get(0);
    assert_eq!(
        singleton_columns, 0,
        "pipeline_runs must not contain singleton settlement state"
    );

    let role = format!("pipeline_schema_runtime_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!(
            "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; \
             GRANT {role} TO CURRENT_USER; \
             GRANT USAGE ON SCHEMA public TO {role}; \
             GRANT SELECT, INSERT, UPDATE ON pipeline_bundle_packages, \
                 pipeline_run_settlements TO {role};"
        ))
        .await
        .expect("create and grant the dedicated NOBYPASSRLS runtime role");

    let role_flags = admin
        .query_one(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1",
            &[&role],
        )
        .await
        .expect("read runtime role flags");
    assert!(!role_flags.get::<_, bool>(0), "runtime role is a superuser");
    assert!(!role_flags.get::<_, bool>(1), "runtime role has BYPASSRLS");

    let suffix = Uuid::new_v4().simple().to_string();
    let tenant_a = format!("pipeline-upgrade-a-{suffix}");
    let tenant_b = format!("pipeline-upgrade-b-{suffix}");
    let submission_id = Uuid::new_v4();
    let trace_id = Uuid::new_v4();
    let object_ref_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    set_tenant(&admin, &tenant_a).await;
    admin
        .execute(
            "INSERT INTO trace_tenants (tenant_id) VALUES ($1)",
            &[&tenant_a],
        )
        .await
        .expect("insert first upgrade tenant");
    admin
        .execute(
            "INSERT INTO pipeline_bundle_packages \
             (tenant_id, bundle_id, manifest_format_version, package) \
             VALUES ($1, $2, 1, '{}'::jsonb)",
            &[&tenant_a, &format!("sha256:{}", "a".repeat(64))],
        )
        .await
        .expect("insert first tenant package");
    admin
        .execute(
            "INSERT INTO trace_submissions (\
                 tenant_id, submission_id, trace_id, auth_principal_ref,\
                 schema_version, consent_policy_version, retention_policy_id,\
                 status, privacy_risk, redaction_pipeline_version, redaction_hash\
             ) VALUES (\
                 $1, $2, $3, 'principal_sha256:pipeline_upgrade',\
                 'trace.contribution.v1', 'consent.v1', 'retention.v1',\
                 'accepted', 'low', 'redaction.v1', 'sha256:pipeline-upgrade'\
             )",
            &[&tenant_a, &submission_id, &trace_id],
        )
        .await
        .expect("insert pipeline upgrade submission");
    admin
        .execute(
            "INSERT INTO trace_object_refs (\
                 tenant_id, submission_id, object_ref_id, artifact_kind,\
                 object_store, object_key, content_sha256, encryption_key_ref, size_bytes\
             ) VALUES ($1, $2, $3, 'redacted_trace', 'test', 'object-key',\
                 $4, 'test-key', 1)",
            &[&tenant_a, &submission_id, &object_ref_id, &"c".repeat(64)],
        )
        .await
        .expect("insert pipeline upgrade object reference");
    admin
        .execute(
            "INSERT INTO pipeline_runs (\
                 tenant_id, run_id, submission_id, trace_id, bundle_id,\
                 request_idempotency_key, request_content_hash, source_object_ref_id,\
                 next_phase, state\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'settle', 'pending')",
            &[
                &tenant_a,
                &run_id,
                &submission_id,
                &trace_id,
                &format!("sha256:{}", "a".repeat(64)),
                &format!("sha256:{}", "d".repeat(64)),
                &format!("sha256:{}", "e".repeat(64)),
                &object_ref_id,
            ],
        )
        .await
        .expect("insert pipeline upgrade run");
    admin
        .execute(
            "INSERT INTO pipeline_run_settlements (\
                 tenant_id, run_id, instrument_id, atomic_units,\
                 operation_ref_hash, payout_rail, payout_state\
             ) VALUES\
                 ($1, $2, 'trace_credit', 3, $3, 'near', 'disabled'),\
                 ($1, $2, 'storage_rebate', 7, $4, 'none', 'disabled')",
            &[
                &tenant_a,
                &run_id,
                &format!("sha256:{}", "f".repeat(64)),
                &format!("sha256:{}", "0".repeat(64)),
            ],
        )
        .await
        .expect("insert two independent instrument settlements");
    assert_eq!(
        admin
            .query_one(
                "SELECT COUNT(*) FROM pipeline_run_settlements WHERE run_id = $1",
                &[&run_id],
            )
            .await
            .expect("count instrument settlements")
            .get::<_, i64>(0),
        2,
        "one run must retain both instrument operations"
    );
    assert!(
        admin
            .execute(
                "INSERT INTO pipeline_run_settlements (\
                     tenant_id, run_id, instrument_id, atomic_units,\
                     operation_ref_hash, payout_rail, payout_state\
                 ) VALUES ($1, $2, 'trace_credit', 9, $3, 'near', 'disabled')",
                &[&tenant_a, &run_id, &format!("sha256:{}", "1".repeat(64)),],
            )
            .await
            .is_err(),
        "the run/instrument key must reject a duplicate instrument"
    );
    assert!(
        admin
            .execute(
                "UPDATE pipeline_run_settlements SET atomic_units = 4 \
                 WHERE tenant_id = $1 AND run_id = $2 AND instrument_id = 'trace_credit'",
                &[&tenant_a, &run_id],
            )
            .await
            .is_err(),
        "settlement identity fields must be immutable"
    );
    assert!(
        admin
            .execute(
                "UPDATE pipeline_run_settlements SET operation_state = 'leased' \
                 WHERE tenant_id = $1 AND run_id = $2 AND instrument_id = 'trace_credit'",
                &[&tenant_a, &run_id],
            )
            .await
            .is_err(),
        "a leased settlement must carry a lease token and expiry"
    );
    set_tenant(&admin, &tenant_b).await;
    admin
        .execute(
            "INSERT INTO trace_tenants (tenant_id) VALUES ($1)",
            &[&tenant_b],
        )
        .await
        .expect("insert second upgrade tenant");
    admin
        .execute(
            "INSERT INTO pipeline_bundle_packages \
             (tenant_id, bundle_id, manifest_format_version, package) \
             VALUES ($1, $2, 1, '{}'::jsonb)",
            &[&tenant_b, &format!("sha256:{}", "b".repeat(64))],
        )
        .await
        .expect("insert second tenant package");
    admin
        .execute(
            "SELECT set_config('trace_commons.trace_tenant_id', '', false)",
            &[],
        )
        .await
        .expect("clear tenant context before the fail-closed probe");

    let transaction = admin.transaction().await.expect("start runtime RLS probe");
    transaction
        .batch_execute(&format!("SET LOCAL ROLE {role}"))
        .await
        .expect("SET ROLE to the dedicated NOBYPASSRLS runtime role");

    let visible_without_tenant: i64 = transaction
        .query_one("SELECT COUNT(*) FROM pipeline_bundle_packages", &[])
        .await
        .expect("query pipeline packages without tenant context")
        .get(0);
    assert_eq!(
        visible_without_tenant, 0,
        "pipeline RLS must fail closed without tenant context"
    );

    transaction
        .execute(
            "SELECT set_config('trace_commons.trace_tenant_id', $1, true)",
            &[&tenant_a],
        )
        .await
        .expect("bind runtime role to the first tenant");
    let visible_for_tenant: Vec<String> = transaction
        .query("SELECT tenant_id FROM pipeline_bundle_packages", &[])
        .await
        .expect("query tenant-scoped pipeline packages")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(visible_for_tenant, std::slice::from_ref(&tenant_a));
    assert_eq!(
        transaction
            .query_one("SELECT COUNT(*) FROM pipeline_run_settlements", &[])
            .await
            .expect("query tenant-scoped instrument settlements")
            .get::<_, i64>(0),
        2,
        "the runtime role must see both and only its tenant's instrument operations"
    );

    let pipeline_tables = TRACE_COMMONS_RLS_TABLES
        .iter()
        .filter(|table| table.starts_with("pipeline_") || **table == "phase_outcomes")
        .copied()
        .collect::<Vec<_>>();
    let qualified_tables: i64 = transaction
        .query_one(
            "SELECT COUNT(*) \
             FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' \
               AND c.relname::text = ANY($1) \
               AND c.relrowsecurity \
               AND c.relforcerowsecurity",
            &[&pipeline_tables],
        )
        .await
        .expect("inspect forced RLS as the runtime role")
        .get(0);
    assert_eq!(
        usize::try_from(qualified_tables).expect("nonnegative qualified table count"),
        pipeline_tables.len(),
        "every pipeline table must enable and force RLS"
    );
    transaction
        .commit()
        .await
        .expect("commit runtime RLS probe");

    admin
        .batch_execute(&format!(
            "DROP OWNED BY {role}; REVOKE {role} FROM CURRENT_USER; DROP ROLE {role};"
        ))
        .await
        .expect("remove dedicated runtime role");
}
