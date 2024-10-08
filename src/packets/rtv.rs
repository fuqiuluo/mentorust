use bytes::{BufMut, Bytes, BytesMut};
use crate::eap::utils::{check_sum, encrypt_rtv};

const RTV_FLAG: u32 = 0x00_00_13_11;

const RTV_ID_EMPTY: u8 = 0x02;
const RTV_ID_RANDOM_STRING: u8 = 0x17;
const RTV_ID_DHCP_FLAG: u8 = 0x18;
const RTV_ID_MAC: u8 = 0x2d;
const RTV_ID_V4_HASH: u8 = 0x2f;
const RTV_ID_IPV6_COUNT: u8 = 0x35;
const RTV_ID_LL_IPV6: u8 = 0x36;
const RTV_ID_LL_IPV6_T: u8 = 0x38;
const RTV_ID_SERVICE: u8 = 0x39;
const RTV_ID_MSG: u8 = 0x3c;
const RTV_ID_GLB_IPV6: u8 = 0x4e;
const RTV_ID_V3_HASH: u8 = 0x4d;
const RTV_ID_HDD_SER: u8 = 0x54;
const RTV_ID_DOMAIN_NAME: u8 = 0x55;
const RTV_ID_RJ_VER: u8 = 0x62;
const RTV_ID_DSMSCL_EXITS: u8 = 0x6b;
const RTV_ID_VER_STR: u8 = 0x6f;
const RTV_ID_OS_BITS: u8 = 0x70;
const RTV_ID_DNS: u8 = 0x76;
const RTV_ID_UNK_1: u8 = 0x79;

pub fn rtv_net_config(
    ipv4: &[u8],
) -> Vec<u8> {
    let mut net_data = BytesMut::new();
    net_data.put_u32(RTV_FLAG);
    net_data.put_u8(1);
    net_data.put_slice(ipv4);
    net_data.put_slice(&[255, 255, 0, 0]);
    net_data.put_slice(&[ipv4[0], ipv4[1], 255, 254]);
    net_data.put_slice(&[114, 114, 114, 114]);
    let sum = check_sum(net_data.as_ref());
    net_data.put_slice(&sum);
    let net_data = encrypt_rtv(net_data.as_ref());

    net_data
}

pub fn rtv_process_name() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    const PROCESS_NAME: &'static str = "8021x.exe";
    const REST_LEN: usize = 32 - PROCESS_NAME.len();
    pkt.put_slice(PROCESS_NAME.as_bytes());
    pkt.put_slice(&[0u8; REST_LEN]);
    pkt.put_slice(&[0x06, 0x29, 0x03, 0x00]); // version
    pkt.put_u8(0);

    pkt.freeze()
}

pub fn rtv_empty() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_EMPTY);
    pkt.put_u8(4); // len
    pkt.put_u16(0x1a_28);
    pkt.freeze()
}

pub fn rtv_random_string() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_RANDOM_STRING);
    pkt.put_u8(0x22); // len
    //pkt.put_slice("39696D61260338E95A810388498639f4".as_bytes());
    pkt.put_slice("2D3657A572A25B7D19680388498639f4".as_bytes());
    pkt.put_u16(0x1a_0c);
    pkt.freeze()
}

pub fn rtv_dhcp_flag() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_DHCP_FLAG);
    pkt.put_u8(0x06); // len
    let enable_dhcp = std::env::var("EAPOL_ENABLE_DHCP")
        .map_or(false, |v| v == "1");
    pkt.put_u32(if enable_dhcp { 1 } else { 0 });
    pkt.put_u16(0x1a_0e);
    pkt.freeze()
}

pub fn rtv_mac(mac: &[u8]) -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_MAC);
    pkt.put_u8(0x08); // len
    assert_eq!(mac.len(), 6);
    pkt.put_slice(mac);
    pkt.put_u16(0x1a_18);
    pkt.freeze()
}

pub fn rtv_v4_hash() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_V4_HASH);
    pkt.put_u8(0x12);
    //const DEFAULT_V4_HASH: [u8; 16] = [
    //    0xeb, 0x4f, 0x52, 0x5e, 0x99, 0xff, 0xeb, 0xb1, 0x9d, 0xd2, 0x7b, 0x33, 0x5c, 0x0a, 0x13, 0xbb
    //];
    //pkt.put_slice(&DEFAULT_V4_HASH);
    pkt.put_slice(&[0u8; 16]);
    pkt.put_u16(0x1a_09);
    pkt.freeze()
}

pub fn rtv_ipv6_count() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_IPV6_COUNT);
    pkt.put_u8(0x03);
    pkt.put_u8(0x01);
    pkt.put_u16(0x1a_18);
    pkt.freeze()
}

pub fn rtv_ll_ipv6() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_LL_IPV6);
    pkt.put_u8(0x12);
    pkt.put_slice(&[0u8; 16]);
    pkt.put_u16(0x1a_18);
    pkt.freeze()
}

pub fn rtv_ll_ipv6_t(
    ipv6: &[u8],
) -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_LL_IPV6_T);
    pkt.put_u8(0x12);
    assert_eq!(ipv6.len(), 16);
    if ipv6[0] == 0x00 {
        const DEFAULT_IPV6: [u8; 16] = [
            0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xfc, 0xf5, 0x9b, 0xc0,
            0xcf, 0x51, 0xaa, 0x74,
        ];
        pkt.put_slice(&DEFAULT_IPV6);
    } else {
        pkt.put_slice(ipv6);
    }

    pkt.put_u16(0x1a_18);
    pkt.freeze()
}

pub fn rtv_global_ipv6() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_GLB_IPV6);
    pkt.put_u8(0x12);
    pkt.put_slice(&[0u8; 16]);
    pkt.put_u16(0x1a_88);
    pkt.freeze()
}

pub fn rtv_v3_hash() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_V3_HASH);
    pkt.put_u8(0x82);
    pkt.put_slice("b464896d8135ee1da7dd2926bcbb65ae4eb77df681012a8e52ce8bf566125194ed197bcfda8f729f582a1d330d5f03ba48245a8325f1215ebbe4cf9c1ca25b0b".as_bytes());
    pkt.put_u16(0x1a_28);
    pkt.freeze()
}

pub fn rtv_service() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_SERVICE);
    let service = std::env::var("EAPOL_SERVICE")
        .unwrap_or("".to_string());
    pkt.put_u8(0x22);
    if service.is_empty() {
        pkt.put_slice(&[0xbb, 0xa5, 0xc1, 0xaa ,0xcd, 0xf8]);
        pkt.put_slice(&[0u8; 32 - 6]);
    } else {
        pkt.put_slice(service.as_bytes());
        pkt.put_slice(vec![0u8; 32 - service.len()].as_slice());
    }
    pkt.put_u16(0x1a_48);
    pkt.freeze()
}

pub fn rtv_hdd_ser() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_HDD_SER);
    pkt.put_u8(0x42);
    let ser = std::env::var("EAPOL_HDD_SER")
        .unwrap_or("Static:AB45A862".to_string());
    pkt.put_slice(ser.as_bytes());
    pkt.put_slice(vec![0u8; 64 - ser.len()].as_slice());
    pkt.put_u16(0x1a_09);
    pkt.freeze()
}

pub fn rtv_rj_ver() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_RJ_VER);
    pkt.put_u8(0x03);
    pkt.put_u8(0x0);
    pkt.put_u16(0x1a_09);
    pkt.freeze()
}

pub fn rtv_dsmscl_exits() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_DSMSCL_EXITS);
    pkt.put_u8(0x03);
    pkt.put_u8(0x0);
    pkt.put_u16(0x1a_09);
    pkt.freeze()
}

pub fn rtv_os_bits() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_OS_BITS);
    pkt.put_u8(0x03);
    pkt.put_u8(0x40);
    pkt.put_u16(0x1a_09);
    pkt.freeze()
}

pub fn rtv_client_ver() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_VER_STR);
    pkt.put_u8(0x03);
    pkt.put_u8(0);
    pkt.put_u16(0x1a_09);
    pkt.freeze()
}

pub fn rtv_unk_1() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_UNK_1);
    pkt.put_u8(0x03);
    pkt.put_u8(0x2);
    pkt.put_u16(0x1a_34);
    pkt.freeze()
}

pub fn rtv_dns() -> Bytes {
    let mut pkt = BytesMut::new();
    pkt.put_u32(RTV_FLAG);
    pkt.put_u8(RTV_ID_DNS);
    pkt.put_u8(23 + 2);
    pkt.put_slice("1.1.1.1;8.8.8.8;8.8.4.4".as_bytes());
    pkt.freeze()
}

#[test]
fn test_pack_empty() {
    let pkt = rtv_empty();
    assert_eq!(pkt.len(), 8);
    println!("{:?}", hex::encode(pkt.as_ref()));
}