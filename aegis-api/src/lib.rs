pub mod convert;
pub mod routes;
pub mod state;

pub mod proto {
    tonic::include_proto!("aegis");
}
