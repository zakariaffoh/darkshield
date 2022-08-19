pub trait SqlCriteria {
    fn clause(&mut self, index: u16) -> String;
    fn current_index(&self) -> u16;
}

pub struct ComaparableSqlClause {
    column: String,
    op: String,
    index: u16,
}

impl ComaparableSqlClause {
    fn new(colum: String, op: String) -> Self {
        Self {
            column: colum,
            op: op,
            index: 0,
        }
    }
}

impl SqlCriteria for ComaparableSqlClause {
    fn clause(&mut self, index: u16) -> String {
        self.index = index;
        format!("{} {} ${}", self.column, self.op, self.index)
    }

    fn current_index(&self) -> u16 {
        self.index + 1
    }
}

pub struct InSqlClause {
    column: String,
    op: String,
    index: u16,
    in_count: u16,
}

impl InSqlClause {
    fn new(colum: String, op: String, in_count: u16) -> Self {
        Self {
            column: colum,
            op: op,
            index: 0,
            in_count: in_count,
        }
    }
}

impl SqlCriteria for InSqlClause {
    fn clause(&mut self, index: u16) -> String {
        self.index = index;
        let indices: Vec<String> = (self.index..(self.index + self.in_count))
            .into_iter()
            .map(|id| format!("${}", id))
            .collect();
        format!("{} {} ({})", self.column, self.op, indices.join(","))
    }

    fn current_index(&self) -> u16 {
        self.index + self.in_count
    }
}

pub struct NullSqlClause {
    column: String,
    op: String,
    index: u16,
}

#[allow(dead_code)]
impl NullSqlClause {
    fn new(column: String, op: String) -> Self {
        Self {
            column: column,
            op: op,
            index: 0,
        }
    }
}

impl SqlCriteria for NullSqlClause {
    fn clause(&mut self, index: u16) -> String {
        self.index = index;
        format!("{} {}", self.column, self.op)
    }

    fn current_index(&self) -> u16 {
        self.index
    }
}

pub struct SqlCriteriaBuilder {}

#[allow(dead_code)]
impl SqlCriteriaBuilder {
    fn is_equals(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, "=".to_owned()))
    }

    fn is_less_than(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, "<".to_owned()))
    }

    fn is_less_or_equals(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, "<=".to_owned()))
    }

    fn is_greater_than(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, ">".to_owned()))
    }

    fn is_greater_or_equals(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, ">=".to_owned()))
    }

    fn is_not_equals(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, "<>".to_owned()))
    }

    fn is_null(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, "IS NULL".to_owned()))
    }

    fn is_not_null(column: String) -> Box<dyn SqlCriteria> {
        Box::new(ComaparableSqlClause::new(column, "IS NOT NULL".to_owned()))
    }

    fn is_in(column: String, in_count: u16) -> Box<dyn SqlCriteria> {
        Box::new(InSqlClause::new(column, "IN".to_owned(), in_count))
    }

    fn is_not_in(column: String, in_count: u16) -> Box<dyn SqlCriteria> {
        Box::new(InSqlClause::new(column, "NOT IN".to_owned(), in_count))
    }
}

#[allow(dead_code)]
fn build_sql_where_clause(criteria: &mut Vec<Box<dyn SqlCriteria>>, start_index: u16) -> String {
    let mut clauses = Vec::new();
    let mut index = start_index;
    for cr in criteria.iter_mut() {
        clauses.push(cr.clause(index));
        index = cr.current_index();
    }
    clauses.join(" AND ")
}

#[allow(dead_code)]
pub struct InsertRequestBuilder {
    table_name: Option<String>,
    connection_pool: Option<String>,
    columns: Option<Vec<String>>,
    resolve_conflict: Option<bool>,
}

#[allow(dead_code)]
impl InsertRequestBuilder {
    pub fn new() -> Self {
        Self {
            table_name: None,
            connection_pool: None,
            columns: None,
            resolve_conflict: None,
        }
    }

    pub fn table_name(mut self, table_name: String) -> InsertRequestBuilder {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(mut self, connection_pool: String) -> InsertRequestBuilder {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn columns(mut self, columns: Vec<String>) -> InsertRequestBuilder {
        self.columns = Some(columns);
        self
    }

    pub fn resolve_conflict(mut self, resolve_conflict: bool) -> InsertRequestBuilder {
        self.resolve_conflict = Some(resolve_conflict);
        self
    }

    fn sql_query(&mut self) -> Result<String, String> {
        if self.table_name.is_none()
            || self.columns.is_none()
            || self.columns.as_ref().unwrap().is_empty()
        {
            return Err("Invalid request builder".to_owned());
        }
        let columns = self.columns.as_ref().unwrap().join(",");
        let values_indices: Vec<usize> = (1..(self.columns.as_ref().unwrap().len() + 1)).collect();
        let values_inter: Vec<String> = values_indices
            .into_iter()
            .map(|index| format!("${}", index.to_string()))
            .collect();
        let values = values_inter.join(",");
        if let Some(resolve_conflict) = self.resolve_conflict {
            if resolve_conflict {
                return Ok(format!(
                    "INSERT INTO {} ({}) VALUES({}) ON CONFLICT DO NOTHING",
                    self.table_name.as_ref().unwrap(),
                    columns,
                    values
                ));
            }
        }
        Ok(format!(
            "INSERT INTO {} ({}) VALUES({})",
            self.table_name.as_ref().unwrap(),
            columns,
            values
        ))
    }
}

#[allow(dead_code)]
pub struct UpdateRequestBuilder {
    table_name: Option<String>,
    connection_pool: Option<String>,
    columns: Option<Vec<String>>,
    manage_version: Option<bool>,
    clauses: Option<Vec<Box<dyn SqlCriteria>>>,
}

#[allow(dead_code)]
impl UpdateRequestBuilder {
    pub fn new() -> Self {
        Self {
            table_name: None,
            connection_pool: None,
            columns: None,
            manage_version: None,
            clauses: None,
        }
    }
    pub fn table_name(mut self, table_name: String) -> UpdateRequestBuilder {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(mut self, connection_pool: String) -> UpdateRequestBuilder {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn columns(mut self, columns: Vec<String>) -> UpdateRequestBuilder {
        self.columns = Some(columns);
        self
    }

    pub fn manage_version(mut self, manage_version: bool) -> UpdateRequestBuilder {
        self.manage_version = Some(manage_version);
        self
    }

    pub fn clauses(mut self, clauses: Vec<Box<dyn SqlCriteria>>) -> UpdateRequestBuilder {
        self.clauses = Some(clauses);
        self
    }

    fn sql_query(mut self) -> Result<String, String> {
        if self.table_name.is_none()
            || self.columns.is_none()
            || self.columns.as_ref().unwrap().is_empty()
            || self.clauses.is_none()
            || self.clauses.as_ref().unwrap().is_empty()
        {
            return Err("Invalid request builder".to_owned());
        }
        let columns_with_indices: Vec<String> = self
            .columns
            .as_ref()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, data)| format!("{}=${}", data, i + 1))
            .collect();

        let mut columns = columns_with_indices.join(",");
        let table_name = self.table_name.as_ref().unwrap();

        if let Some(_) = self.manage_version {
            columns = format!("{}, version = version + 1", columns);
        }

        let mut where_clause = "".to_owned();
        let column_count = self.columns.as_deref().unwrap().len() as u16;
        if let Some(clauses) = &mut self.clauses {
            where_clause = build_sql_where_clause(clauses, column_count + 1);
        }
        Ok(format!(
            "UPDATE {} SET {} WHERE {}",
            table_name, columns, where_clause
        ))
    }
}

pub struct DeleteQueryBuilder {
    table_name: Option<String>,
    connection_pool: Option<String>,
    clauses: Option<Vec<Box<dyn SqlCriteria>>>,
}

#[allow(dead_code)]
impl DeleteQueryBuilder {
    pub fn new() -> Self {
        Self {
            table_name: None,
            connection_pool: None,
            clauses: None,
        }
    }

    pub fn table_name(mut self, table_name: String) -> DeleteQueryBuilder {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(mut self, connection_pool: String) -> DeleteQueryBuilder {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn where_clauses(mut self, clauses: Vec<Box<dyn SqlCriteria>>) -> DeleteQueryBuilder {
        self.clauses = Some(clauses);
        self
    }

    fn sql_query(mut self) -> Result<String, String> {
        if let None = self.table_name {
            return Err("Invalid delete query state".to_owned());
        }
        if let Some(clauses) = &mut self.clauses {
            let clause_sql = build_sql_where_clause(clauses, 1);
            Ok(format!(
                "DELETE FROM {}  WHERE {}",
                self.table_name.as_ref().unwrap(),
                clause_sql
            ))
        } else {
            return Ok(format!(
                "DELETE FROM {} ",
                self.table_name.as_ref().unwrap()
            ));
        }
    }
}

pub struct InQueryBuilder {
    start_index: u32,
    end_index: u32,
}

#[allow(dead_code)]
impl InQueryBuilder {
    fn sql_query(&self) -> Result<String, String> {
        let placeholders: Vec<String> = (self.start_index..(self.start_index + self.end_index))
            .into_iter()
            .map(|d| format!("${}", d))
            .collect();
        Ok(format!("({})", placeholders.join(",")))
    }
}

#[allow(dead_code)]
pub struct PaginationOptions {
    start_index: u32,
    max_result: u32,
}

#[allow(dead_code)]
pub struct SelectFromQueryWithPaginationQueryBuilder {
    select_query: String,
    pagination_option: Option<PaginationOptions>,
}

#[allow(dead_code)]
impl SelectFromQueryWithPaginationQueryBuilder {
    pub fn new(query: String) -> Self {
        Self {
            select_query: query,
            pagination_option: None,
        }
    }

    pub fn pagination_option(&mut self, pagination_option: PaginationOptions) -> &mut Self {
        self.pagination_option = Some(pagination_option);
        self
    }

    fn sql_query(&self) -> Result<String, String> {
        if self.select_query.is_empty() {
            return Err("No root query is provided".to_owned());
        }
        if self.pagination_option.is_some() {
            let options = self.pagination_option.as_ref().unwrap();
            return Ok(format!(
                "{} OFFSET {} LIMIT {}",
                self.select_query, options.start_index, options.max_result
            ));
        }
        Ok(self.select_query.clone())
    }
}

#[allow(dead_code)]
pub struct SelectRequestBuilder {
    table_name: Option<String>,
    connection_pool: Option<String>,
    columns: Option<Vec<String>>,
    clauses: Option<Vec<Box<dyn SqlCriteria>>>,
    pagination_options: Option<PaginationOptions>,
}

#[allow(dead_code)]
impl SelectRequestBuilder {
    pub fn new() -> Self {
        Self {
            table_name: None,
            connection_pool: None,
            columns: None,
            clauses: None,
            pagination_options: None,
        }
    }

    pub fn table_name(mut self, table_name: String) -> SelectRequestBuilder {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(mut self, connection_pool: String) -> SelectRequestBuilder {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn columns(mut self, columns: Vec<String>) -> SelectRequestBuilder {
        self.columns = Some(columns);
        self
    }

    pub fn pagination_options(mut self, options: PaginationOptions) -> SelectRequestBuilder {
        self.pagination_options = Some(options);
        self
    }

    pub fn where_clauses(mut self, clause: Vec<Box<dyn SqlCriteria>>) -> SelectRequestBuilder {
        self.clauses = Some(clause);
        self
    }

    #[allow(dead_code)]
    fn sql_query(mut self) -> Result<String, String> {
        if self.table_name.is_none() {
            return Err("Invalid request builder".to_owned());
        }
        let table_name = self.table_name.as_ref().unwrap();
        let selected_columns;
        if let Some(colums) = self.columns {
            selected_columns = colums.join(",");
        } else {
            selected_columns = "*".to_owned();
        }
        let sql_clause;
        if let Some(clauses) = &mut self.clauses {
            let where_clause = build_sql_where_clause(clauses, 1);
            sql_clause = format!(
                "SELECT {} FROM {} WHERE {}",
                selected_columns, table_name, where_clause
            );
        } else {
            sql_clause = format!("SELECT {} FROM {}", selected_columns, table_name);
        }

        let mut pagination = "".to_string();
        if let Some(pagination_option) = &self.pagination_options {
            pagination = format!(
                "OFFSET {} LIMIT {}",
                pagination_option.start_index, pagination_option.max_result
            );
        }
        Ok(format!("{} {}", sql_clause, pagination))
    }
}

#[allow(dead_code)]
pub struct SelectCountRequestBuilder {
    table_name: Option<String>,
    connection_pool: Option<String>,
    clauses: Option<Vec<Box<dyn SqlCriteria>>>,
}

#[allow(dead_code)]
impl SelectCountRequestBuilder {
    pub fn new() -> Self {
        Self {
            table_name: None,
            connection_pool: None,
            clauses: None,
        }
    }

    pub fn table_name(mut self, table_name: String) -> SelectCountRequestBuilder {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(mut self, connection_pool: String) -> SelectCountRequestBuilder {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn where_clauses(
        mut self,
        clauses: Vec<Box<dyn SqlCriteria>>,
    ) -> SelectCountRequestBuilder {
        self.clauses = Some(clauses);
        self
    }

    fn sql_query(mut self) -> Result<String, String> {
        if let None = self.table_name {
            return Err("Invalid request builder".to_owned());
        }
        let table_name = self.table_name.as_ref().unwrap();
        let sql_clause;
        if let Some(clauses) = &mut self.clauses {
            let where_clause = build_sql_where_clause(clauses, 1);
            sql_clause = format!("SELECT COUNT(*) FROM {} WHERE {}", table_name, where_clause);
        } else {
            sql_clause = format!("SELECT COUNT(*) FROM {}", table_name);
        }
        Ok(sql_clause)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_comparable_sql_clause() {
        let comp_op = ComaparableSqlClause::new("id".to_owned(), "=".to_owned());
        assert_eq!(comp_op.column, "id");
        assert_eq!(comp_op.op, "=");
    }

    #[test]
    fn test_in_sql_clause_sql_clause() {
        let in_op = InSqlClause::new("id".to_owned(), "IN".to_owned(), 10);
        assert_eq!(in_op.column, "id");
        assert_eq!(in_op.op, "IN");
        assert_eq!(in_op.in_count, 10);
    }

    #[test]
    fn test_comaparable_sql_clause_clause() {
        {
            let mut comp_op = ComaparableSqlClause::new("id".to_owned(), "=".to_owned());
            assert_eq!(comp_op.clause(1), "id = $1");
            assert_eq!(comp_op.current_index(), 2);
        }
        {
            let mut comp_op = ComaparableSqlClause::new("id".to_owned(), ">".to_owned());
            assert_eq!(comp_op.clause(10), "id > $10");
            assert_eq!(comp_op.current_index(), 11);
        }
        {
            let mut comp_op = ComaparableSqlClause::new("id".to_owned(), "<".to_owned());
            assert_eq!(comp_op.clause(1), "id < $1");
            assert_eq!(comp_op.current_index(), 2);
        }
        {
            let mut comp_op = ComaparableSqlClause::new("id".to_owned(), "<=".to_owned());
            assert_eq!(comp_op.clause(1), "id <= $1");
            assert_eq!(comp_op.current_index(), 2);
        }
        {
            let mut comp_op = ComaparableSqlClause::new("id".to_owned(), ">=".to_owned());
            assert_eq!(comp_op.clause(1), "id >= $1");
            assert_eq!(comp_op.current_index(), 2);
        }
        {
            let mut comp_op = ComaparableSqlClause::new("id".to_owned(), "<>".to_owned());
            assert_eq!(comp_op.clause(1), "id <> $1");
            assert_eq!(comp_op.current_index(), 2);
        }
    }

    #[test]
    fn test_in_sql_clause_clause() {
        {
            let mut comp_op = InSqlClause::new("id".to_owned(), "IN".to_owned(), 1);
            assert_eq!(comp_op.clause(1), "id IN ($1)");
            assert_eq!(comp_op.current_index(), 2);
        }
        {
            let mut comp_op = InSqlClause::new("id".to_owned(), "IN".to_owned(), 10);
            assert_eq!(comp_op.clause(1), "id IN ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)");
            assert_eq!(comp_op.current_index(), 11);
        }
        {
            let mut comp_op = InSqlClause::new("id".to_owned(), "NOT IN".to_owned(), 10);
            assert_eq!(
                comp_op.clause(1),
                "id NOT IN ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
            );
            assert_eq!(comp_op.current_index(), 11);
        }
    }

    #[test]
    fn test_null_sql_clause_clause() {
        {
            let mut null_op = NullSqlClause::new("id".to_owned(), "IS NULL".to_owned());
            assert_eq!(null_op.clause(1), "id IS NULL");
            assert_eq!(null_op.current_index(), 1);
        }
        {
            let mut null_op = NullSqlClause::new("id".to_owned(), "IS NOT NULL".to_owned());
            assert_eq!(null_op.clause(1), "id IS NOT NULL");
            assert_eq!(null_op.current_index(), 1);
        }
    }

    #[test]
    fn test_sql_criteria_builder() {
        {
            assert_eq!(
                SqlCriteriaBuilder::is_equals("id".to_owned()).clause(1),
                "id = $1"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_not_equals("id".to_owned()).clause(1),
                "id <> $1"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_less_than("id".to_owned()).clause(1),
                "id < $1"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_less_or_equals("id".to_owned()).clause(1),
                "id <= $1"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_greater_than("id".to_owned()).clause(1),
                "id > $1"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_greater_or_equals("id".to_owned()).clause(1),
                "id >= $1"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_not_in("id".to_owned(), 10).clause(1),
                "id NOT IN ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
            );
        }
        {
            assert_eq!(
                SqlCriteriaBuilder::is_in("id".to_owned(), 10).clause(1),
                "id IN ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
            );
        }
    }

    #[test]
    fn test_build_sql_where_clause() {
        {
            let mut clauses = vec![
                SqlCriteriaBuilder::is_less_than("id".to_owned()),
                SqlCriteriaBuilder::is_greater_than("tenant".to_owned()),
            ];
            assert_eq!(
                build_sql_where_clause(&mut clauses, 1),
                "id < $1 AND tenant > $2"
            );
        }
        {
            let mut clauses = vec![
                SqlCriteriaBuilder::is_in("id".to_owned(), 10),
                SqlCriteriaBuilder::is_greater_than("tenant".to_owned()),
            ];
            assert_eq!(
                build_sql_where_clause(&mut clauses, 1),
                "id IN ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AND tenant > $11"
            );
        }
        {
            let mut clauses = vec![
                SqlCriteriaBuilder::is_equals("id".to_owned()),
                SqlCriteriaBuilder::is_less_than("tenant".to_owned()),
                SqlCriteriaBuilder::is_less_or_equals("version".to_owned()),
                SqlCriteriaBuilder::is_greater_than("name".to_owned()),
                SqlCriteriaBuilder::is_greater_or_equals("description".to_owned()),
            ];
            assert_eq!(
                build_sql_where_clause(&mut clauses, 1),
                "id = $1 AND tenant < $2 AND version <= $3 AND name > $4 AND description >= $5"
            );
        }
        {
            let mut clauses = vec![
                SqlCriteriaBuilder::is_in("id".to_owned(), 2),
                SqlCriteriaBuilder::is_not_in("tenant".to_owned(), 2),
            ];
            assert_eq!(
                build_sql_where_clause(&mut clauses, 1),
                "id IN ($1,$2) AND tenant NOT IN ($3,$4)"
            );
        }
    }

    #[test]
    fn test_select_from_query_with_pagination_query_builder() {
        {
            let mut builder =
                SelectFromQueryWithPaginationQueryBuilder::new("SELECT * FROM USERS".to_string());
            builder.pagination_option(PaginationOptions {
                start_index: 1,
                max_result: 10,
            });
            assert_eq!(
                builder.sql_query().unwrap(),
                "SELECT * FROM USERS OFFSET 1 LIMIT 10"
            );
        }
        {
            let builder =
                SelectFromQueryWithPaginationQueryBuilder::new("SELECT * FROM USERS".to_string());
            assert_eq!(builder.sql_query().unwrap(), "SELECT * FROM USERS");
        }
    }

    #[test]
    fn test_insert_request_builder() {
        {
            let mut builder = InsertRequestBuilder::new()
                .table_name("USERS".to_owned())
                .columns(vec!["id".to_owned()])
                .connection_pool("my_pool".to_owned())
                .resolve_conflict(false);
            assert_eq!(
                builder.sql_query().unwrap(),
                "INSERT INTO USERS (id) VALUES($1)"
            );
        }
        {
            let mut builder = InsertRequestBuilder::new()
                .table_name("USERS".to_owned())
                .columns(vec![
                    "id".to_owned(),
                    "name".to_owned(),
                    "description".to_owned(),
                ])
                .connection_pool("my_pool".to_owned())
                .resolve_conflict(false);
            assert_eq!(
                builder.sql_query().unwrap(),
                "INSERT INTO USERS (id,name,description) VALUES($1,$2,$3)"
            );
        }
    }

    #[test]
    fn test_update_request_builder() {
        {
            let builder = UpdateRequestBuilder::new()
                .table_name("USERS".to_owned())
                .columns(vec![
                    "id".to_owned(),
                    "name".to_owned(),
                    "description".to_owned(),
                ])
                .connection_pool("my_pool".to_owned())
                .clauses(vec![SqlCriteriaBuilder::is_less_than("name".to_owned())])
                .manage_version(true);
            assert_eq!(
                builder.sql_query().unwrap(),
                "UPDATE USERS SET id=$1,name=$2,description=$3, version = version + 1 WHERE name < $4"
            );
        }
        {
            let builder = UpdateRequestBuilder::new()
                .table_name("USERS".to_owned())
                .columns(vec![
                    "id".to_owned(),
                    "name".to_owned(),
                    "description".to_owned(),
                ])
                .connection_pool("my_pool".to_owned())
                .clauses(vec![
                    SqlCriteriaBuilder::is_less_than("name".to_owned()),
                    SqlCriteriaBuilder::is_equals("creation_time".to_owned()),
                ])
                .manage_version(true);
            assert_eq!(
                builder.sql_query().unwrap(),
                "UPDATE USERS SET id=$1,name=$2,description=$3, version = version + 1 WHERE name < $4 AND creation_time = $5"
            );
        }
    }

    #[test]
    fn test_select_request_builder() {
        {
            let builder = SelectRequestBuilder::new()
                .table_name("USERS".to_owned())
                .columns(vec![
                    "id".to_owned(),
                    "name".to_owned(),
                    "description".to_owned(),
                ])
                .connection_pool("my_pool".to_owned())
                .where_clauses(vec![SqlCriteriaBuilder::is_less_than("name".to_owned())]);
            assert_eq!(
                builder.sql_query().unwrap(),
                "SELECT id,name,description FROM USERS WHERE name < $1 "
            );
        }
        {
            let builder = SelectRequestBuilder::new()
                .table_name("USERS".to_owned())
                .columns(vec![
                    "id".to_owned(),
                    "name".to_owned(),
                    "description".to_owned(),
                ])
                .connection_pool("my_pool".to_owned())
                .where_clauses(vec![
                    SqlCriteriaBuilder::is_less_than("name".to_owned()),
                    SqlCriteriaBuilder::is_equals("creation_time".to_owned()),
                ]);
            assert_eq!(
                builder.sql_query().unwrap(),
                "SELECT id,name,description FROM USERS WHERE name < $1 AND creation_time = $2 "
            );
        }
    }

    #[test]
    fn test_select_count_request_builder() {
        {
            let builder = SelectCountRequestBuilder::new()
                .table_name("USERS".to_owned())
                .connection_pool("my_pool".to_owned())
                .where_clauses(vec![SqlCriteriaBuilder::is_less_than("name".to_owned())]);
            assert_eq!(
                builder.sql_query().unwrap(),
                "SELECT COUNT(*) FROM USERS WHERE name < $1"
            );
        }
        {
            let builder = SelectCountRequestBuilder::new()
                .table_name("USERS".to_owned())
                .connection_pool("my_pool".to_owned())
                .where_clauses(vec![
                    SqlCriteriaBuilder::is_less_than("name".to_owned()),
                    SqlCriteriaBuilder::is_equals("creation_time".to_owned()),
                ]);
            assert_eq!(
                builder.sql_query().unwrap(),
                "SELECT COUNT(*) FROM USERS WHERE name < $1 AND creation_time = $2"
            );
        }
    }

    #[test]
    fn test_delete_request_builder() {
        {
            let builder = DeleteQueryBuilder::new()
                .table_name("USERS".to_owned())
                .connection_pool("my_pool".to_owned())
                .where_clauses(vec![SqlCriteriaBuilder::is_less_than("name".to_owned())]);
            assert_eq!(
                builder.sql_query().unwrap(),
                "DELETE FROM USERS  WHERE name < $1"
            );
        }
        {
            let builder = DeleteQueryBuilder::new()
                .table_name("USERS".to_owned())
                .connection_pool("my_pool".to_owned())
                .where_clauses(vec![
                    SqlCriteriaBuilder::is_less_than("name".to_owned()),
                    SqlCriteriaBuilder::is_equals("creation_time".to_owned()),
                ]);
            assert_eq!(
                builder.sql_query().unwrap(),
                "DELETE FROM USERS  WHERE name < $1 AND creation_time = $2"
            );
        }
    }
}
