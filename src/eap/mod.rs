mod state;
pub mod utils;

pub use state::Status;

pub const CODE_REQUEST: u8 = 1;
pub const CODE_RESPONSE: u8 = 2;
pub const CODE_SUCCESS: u8 = 3;
pub const CODE_FAILURE: u8 = 4;
pub const CODE_INITIATE: u8 = 5;
pub const CODE_FINISH: u8 = 6;


pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_MD5_CHALLENGE: u8 = 4;
pub const EAP_TYPE_OTP: u8 = 5;
pub const EAP_TYPE_GTC: u8 = 6;
pub const EAP_TYPE_RSA: u8 = 9;
pub const EAP_TYPE_LEAP: u8 = 17;
pub const EAP_TYPE_SIM: u8 = 18;
pub const EAP_TYPE_TTLS: u8 = 21;