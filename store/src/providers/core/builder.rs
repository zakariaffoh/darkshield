pub struct RequestBuilder {}

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

    pub fn table_name(&mut self, table_name: String) -> &mut Self {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(&mut self, connection_pool: String) -> &mut Self {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn columns(&mut self, columns: Vec<String>) -> &mut Self {
        self.columns = Some(columns);
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
                    "INSERT INTO {} ({}) ON CONFLICT DO NOTHING",
                    columns, values
                ));
            }
        }
        Ok(format!("INSERT INTO {} ({})", columns, values))
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
    pub fn table_name(&mut self, table_name: String) -> &mut Self {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(&mut self, connection_pool: String) -> &mut Self {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn columns(&mut self, columns: Vec<String>) -> &mut Self {
        self.columns = Some(columns);
        self
    }

    pub fn manage_version(&mut self, manage_version: bool) -> &mut Self {
        self.manage_version = Some(manage_version);
        self
    }

    fn sql_query(&mut self) -> Result<String, String> {
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

    pub fn table_name(&mut self, table_name: String) -> &mut Self {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(&mut self, connection_pool: String) -> &mut Self {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn clauses(&mut self, clauses: Vec<Box<dyn SqlCriteria>>) -> &mut Self {
        self.clauses = Some(clauses);
        self
    }

    fn sql_query(&mut self) -> Result<String, String> {
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

    pub fn table_name(&mut self, table_name: String) -> &mut Self {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(&mut self, connection_pool: String) -> &mut Self {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn columns(&mut self, columns: Vec<String>) -> &mut Self {
        self.columns = Some(columns);
        self
    }

    pub fn pagination_options(&mut self, options: PaginationOptions) -> &mut Self {
        self.pagination_options = Some(options);
        self
    }

    pub fn where_clause(&mut self, clause: Vec<Box<dyn SqlCriteria>>) -> &mut Self {
        self.clauses = Some(clause);
        self
    }

    #[allow(dead_code)]
    fn sql_query(&mut self) -> Result<String, String> {
        if self.table_name.is_none() {
            return Err("Invalid request builder".to_owned());
        }
        let table_name = self.table_name.as_ref().unwrap();
        let selected_columns = if self.columns.is_some() {
            "*".to_string()
        } else {
            self.columns.as_ref().unwrap().join(",")
        };

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

    pub fn table_name(&mut self, table_name: String) -> &mut Self {
        self.table_name = Some(table_name);
        self
    }

    pub fn connection_pool(&mut self, connection_pool: String) -> &mut Self {
        self.connection_pool = Some(connection_pool);
        self
    }

    pub fn where_clause(&mut self, clause: Vec<Box<dyn SqlCriteria>>) -> &mut Self {
        self.clauses = Some(clause);
        self
    }

    fn sql_query(&mut self) -> Result<String, String> {
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
