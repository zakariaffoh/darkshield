pub mod aescbc_hmac;
pub mod aesgcm;

use crate::jose::jwe::enc::aesgcm::AESGCMJweEncryption;
pub use AESGCMJweEncryption::A128gcm as A128GCM;
pub use AESGCMJweEncryption::A192gcm as A192GCM;
pub use AESGCMJweEncryption::A256gcm as A256GCM;

use crate::jose::jwe::enc::aescbc_hmac::AESCBCHMACJweEncryption;
pub use AESCBCHMACJweEncryption::A128cbcHs256 as A128CBC_HS256;
pub use AESCBCHMACJweEncryption::A192cbcHs384 as A192CBC_HS384;
pub use AESCBCHMACJweEncryption::A256cbcHs512 as A256CBC_HS512;
