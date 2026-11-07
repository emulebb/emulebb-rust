pub const SCHEMA_ID: &str = "emulebb.metadata.clean-v2";
pub const SCHEMA_VERSION: i64 = 59;
pub const SCHEMA_SQL: &str = include_str!("schema.sql");

#[cfg(test)]
mod tests;
