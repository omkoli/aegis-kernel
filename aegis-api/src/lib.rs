pub mod convert;
pub mod routes;
pub mod state;

#[cfg(feature = "grpc")]
pub mod proto {
    tonic::include_proto!("aegis");
}
