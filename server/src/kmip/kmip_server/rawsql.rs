//! rawsql is a rust library for abstract the sql code in one place and reuse it.
//!
//! Given a sql file stored for example in "examples/postgre.sql":
//!
//! ```sql,no_run
//!
//! -- name: drop-table-person
//! DROP TABLE IF EXISTS "person";
//!
//! -- name: create-table-person
//! CREATE TABLE "person" (id SERIAL PRIMARY KEY, name  VARCHAR NOT NULL, data BYTEA);
//!
//! -- name: insert-person
//! INSERT INTO "person" (name, data) VALUES ($1, $2);
//!
//! -- name: select-all
//! SELECT id, name, data FROM person;
//!
//! ```
//!
//! Use this lib for get each query associated to the "name" declared on the previous sql file:
//!
//! ```rust,no_run
//!
//! extern crate rawsql;
//! extern crate postgres;
//!
//! use rawsql::Loader;
//! use postgres::{Connection, SslMode};
//!
//! struct Person {
//!     id: i32,
//!     name: String,
//!     data: Option<Vec<u8>>
//! }
//!
//! fn main() {
//!     let conn = Connection::connect("postgres://postgres:local@localhost", &SslMode::None).unwrap();
//!
//!     let queries = Loader::je va_queries_from("examples/postgre.sql").unwrap().queries;
//!
//!     //Drop table
//!     conn.execute(queries.get("drop-table-person").unwrap(), &[]).unwrap();
//!
//!     //Create table
//!     conn.execute(queries.get("create-table-person").unwrap(), &[]).unwrap();
//!
//!     let me = Person {
//!         id: 0,
//!         name: "Manuel".to_string(),
//!         data: None
//!     };
//!
//!     //Insert into table
//!     conn.execute(queries.get("insert-person").unwrap(),
//!                  &[&me.name, &me.data]).unwrap();
//!
//!     //Select
//!     let stmt = conn.prepare(queries.get("select-all").unwrap()).unwrap();
//!     for row in stmt.query(&[]).unwrap() {
//!         let person = Person {
//!             id: row.get(0),
//!             name: row.get(1),
//!             data: row.get(2)
//!         };
//!         println!("Found person id : {}, name: {}", person.id, person.name);
//!     }
//! }
//!
//! ```
#![doc(html_root_url = "https://manute.github.io/rawsql")]
#![warn(missing_docs)]

use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Result},
};

struct Parser {
    name: String,
    query: String,
}

impl Parser {
    fn init() -> Parser {
        Parser {
            name: String::new(),
            query: String::new(),
        }
    }

    fn tag_name(&mut self, line: &str) {
        let tag = line
            .replace("--", "")
            .replace("name", "")
            .replace(":", "")
            .trim_left()
            .to_string();
        self.name = tag.to_string();
        self.query = "".to_string();
    }

    fn build_query(&mut self, line: &str) {
        let q = line.trim_left();
        if self.query.is_empty() {
            self.query = q.to_string();
        } else {
            self.query = self.query.to_string() + " " + &q;
        }
    }

    fn is_starting_query(&mut self) -> bool {
        !self.name.is_empty()
    }

    fn is_finishing_query(&mut self, line: &str) -> bool {
        !self.query.is_empty() && line.ends_with(";")
    }

    fn is_tagged_name(&mut self, line: &str) -> bool {
        line.starts_with("--") && line.contains("name")
    }
}

/// All queries info
pub struct Loader {
    /// Queries as key(name) and value(query)
    pub queries: HashMap<String, String>,
}

//TODO: use pub struct Loader(pub HashMap<String, String>) + implement deref

impl Loader {
    ///Given a path of file retrieve all the queries.
    pub fn get_queries_from(content: &str) -> Result<Loader> {
        let mut parser = Parser::init();
        let mut queries: HashMap<String, String> = HashMap::new();

        for line in content.lines() {
            if line.is_empty() {
                continue
            }
            if parser.is_tagged_name(line) {
                parser.tag_name(line);
                continue
            }
            if parser.is_starting_query() {
                parser.build_query(line);
            }
            if parser.is_finishing_query(line) {
                queries.insert(parser.name, parser.query);
                parser = Parser::init()
            }
        }
        Ok(Loader { queries })
    }

    ///Given a path of file retrieve all the queries.
    pub fn read_queries_from(path: &str) -> Result<Loader> {
        let data_file = read_file(path)?;
        Loader::get_queries_from(&data_file)
    }
}

/// Read file data into string from path
fn read_file(path: &str) -> Result<String> {
    let mut file = File::open(&path)?;
    let mut data_file = String::new();
    file.read_to_string(&mut data_file)?;
    Ok(data_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    #[ignore]
    fn it_when_file_not_exists() {
        let loaded = Loader::read_queries_from("examples/non_exist.sql");
        match loaded {
            Ok(r) => r,
            Err(why) => panic!("{}", why),
        };
    }

    #[test]
    #[ignore]
    fn it_should_parse_queries() {
        let loaded = Loader::read_queries_from("examples/example.sql");

        let res = match loaded {
            Ok(r) => r,
            Err(why) => panic!("{}", why),
        };

        let q_simple = match res.queries.get("simple") {
            Some(r) => r,
            None => panic!("no result on get query"),
        };

        assert_eq!(q_simple, "SELECT * FROM table1 u where  u.name = ?;");

        let q_2_lines = match res.queries.get("two-lines") {
            Some(r) => r,
            None => panic!("no result on get query"),
        };

        assert_eq!(q_2_lines, "Insert INTO table2 SELECT * FROM table1;");

        let q_complex = match res.queries.get("complex") {
            Some(r) => r,
            None => panic!("no result on get query"),
        };

        assert_eq!(
            q_complex,
            "SELECT * FROM Customers c INNER JOIN CustomerAccounts ca ON ca.CustomerID = \
             c.CustomerID AND c.State = ? INNER JOIN Accounts a ON ca.AccountID = a.AccountID AND \
             a.Status = ?;"
        );

        let q_psql = match res.queries.get("psql-insert") {
            Some(r) => r,
            None => panic!("no result on get query"),
        };

        assert_eq!(q_psql, "INSERT INTO person (name, data) VALUES ($1, $2);");
    }
}
