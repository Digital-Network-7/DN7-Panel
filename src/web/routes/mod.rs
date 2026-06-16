//! HTTP route table (≈ Laravel `routes/`). Pure assembly: the table itself
//! lives in `table`, bound by the http kernel via `crate::web::routes::build_router`.

mod table;

pub(crate) use table::build_router;
