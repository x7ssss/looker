pub mod error;
pub mod item;
pub mod pool;

pub use error::PoolError;
pub use item::{AnonymityLevel, CheckedProxy, ProxyItem, ProxySnapshot};
pub use pool::{
    export_disk_hierarchy, ApiStatus, HealthyByProto, PoolStats, ProxyApiItem, ProxyPool,
    SelectionStrategy,
};
