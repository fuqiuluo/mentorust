mod rtv;

use std::process::exit;
use bytes::{BufMut, Bytes, BytesMut};
use log::info;
use pnet::datalink::NetworkInterface;
use crate::eap::{CODE_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE};
use crate::eap::utils::{check_sum, encrypt_rtv};

const VERSION_8021X_2001: u8 = 0x1;
const VERSION_8021X_2004: u8 = 0x2;
const VERSION_8021X_2010: u8 = 0x3;

const ETH_P_PAE: u16 = 0x888e;

/// 承载的是EAP消息
const TYPE_EAP_PACKET: u8 = 0x0;
/// 发起认证
const TYPE_EAPOL_START: u8 = 0x1;
/// 下线
const TYPE_EAPOL_LOGOFF: u8 = 0x2;
/// 交换密钥
const TYPE_EAPOL_KEY: u8 = 0x3;
/// EAPOL-ASF-ALERT
const TYPE_EAPOL_ASF_ALERT: u8 = 0x4;
/// HELLO
const TYPE_EAPOL_HEARTBEAT: u8 = 0xbf;

/// 寻找认证服务器
pub fn build_hello_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16 + 2);
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAPOL_START));
    packet.extend_from_slice(&0x0000_i16.to_be_bytes()); // length
    packet
}

/// 发送用户名
pub fn build_identity_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
    ipv4: &[u8],
    ipv6: &[u8],
    identity: &str,
    id: u8
) -> Vec<u8> {
    let eap_len = (identity.len() + 5) as u16; // 锐捷
    let mut packet = BytesMut::new();
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAP_PACKET)); // 16
    packet.put_u16(eap_len);
    packet.put_u8(CODE_RESPONSE); // eap code
    packet.put_u8(id); // eap id
    packet.put_u16(eap_len); // eap len
    packet.put_u8(EAP_TYPE_IDENTITY); // eap type
    packet.put_slice(identity.as_bytes()); // eap identity
    packet.put(build_ruijie_private_extended_data(local_mac, ipv4, ipv6));

    packet.to_vec()
}

/// 发送密码
pub fn build_password_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
    ipv4: &[u8],
    ipv6: &[u8],
    identity: &str,
    password: &str,
    id: u8,
    seed: &[u8]
) -> Vec<u8> {
    let eap_len = (identity.len() + 22) as u16; // 锐捷
    let mut packet = BytesMut::new();
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAP_PACKET)); // 16
    packet.put_u16(eap_len);
    packet.put_u8(CODE_RESPONSE); // eap code
    packet.put_u8(id); // eap id
    packet.put_u16(eap_len); // eap len
    packet.put_u8(EAP_TYPE_MD5_CHALLENGE); // eap type

    packet.put_u8(0x10); // password md5 length
    let mut md5_pwd = BytesMut::with_capacity(password.len() + seed.len() + 1);
    md5_pwd.put_u8(id);
    md5_pwd.put_slice(password.as_bytes());
    md5_pwd.put_slice(seed);
    let md5_pwd = md5::compute(md5_pwd.as_ref()).0;
    if option_env!("MENTORUST_DEBUG") == Some("1") {
        info!("PasswordMD5: {}", hex::encode(&md5_pwd));
    }
    packet.put_slice(&md5_pwd);
    packet.put_slice(identity.as_bytes()); // eap identity
    packet.put(build_ruijie_private_extended_data(local_mac, ipv4, ipv6));

    packet.to_vec()
}

/// 心跳包
pub fn build_heartbeat_packet(
    dest_mac: &[u8],
    local_mac: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16 + 2);
    packet.extend_from_slice(&build_eap(dest_mac, local_mac, ETH_P_PAE, VERSION_8021X_2001, TYPE_EAPOL_HEARTBEAT));

    const ECHO_DATA: [u8; 30] = [
        0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,0x7F,
        0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF,0x00,0x00,0x00
    ];
    packet.put_u16(0x1e);
    packet.extend_from_slice(&ECHO_DATA);

    packet
}

pub(crate) fn build_ruijie_private_extended_data(
    local_mac: &[u8],
    ipv4: &[u8],
    ipv6: &[u8],
) -> Bytes {
    let mut pkt = BytesMut::new();

    pkt.extend_from_slice(rtv::rtv_net_config(ipv4).as_slice());
    pkt.put(rtv::rtv_process_name());
    pkt.put(rtv::rtv_empty());
    pkt.put(rtv::rtv_random_string());
    pkt.put(rtv::rtv_dhcp_flag());
    pkt.put(rtv::rtv_mac(local_mac));
    pkt.put(rtv::rtv_v4_hash());
    pkt.put(rtv::rtv_ipv6_count());
    pkt.put(rtv::rtv_ll_ipv6());
    pkt.put(rtv::rtv_ll_ipv6_t(ipv6));
    pkt.put(rtv::rtv_global_ipv6());
    pkt.put(rtv::rtv_v3_hash());
    pkt.put(rtv::rtv_service());
    pkt.put(rtv::rtv_hdd_ser());
    pkt.put(rtv::rtv_rj_ver());
    pkt.put(rtv::rtv_dsmscl_exits());
    pkt.put(rtv::rtv_os_bits());
    pkt.put(rtv::rtv_client_ver());
    pkt.put(rtv::rtv_unk_1());
    pkt.put(rtv::rtv_dns());

    pkt.freeze()
}

/// 构建eapol包头
pub fn build_eap(
    dest_mac: &[u8],
    local_mac: &[u8],
    proto: u16,
    ver: u8,
    typ: u8,
) -> Vec<u8> {
    let mut head = Vec::with_capacity(12 + 2 + 2);
    head.extend_from_slice(dest_mac);
    head.extend_from_slice(local_mac);
    head.extend_from_slice(&proto.to_be_bytes());
    head.extend_from_slice(&ver.to_be_bytes());
    head.extend_from_slice(&typ.to_be_bytes());
    head // 6+6+2+1+1=16
}

#[test]
fn test_pwd_md5() {
}