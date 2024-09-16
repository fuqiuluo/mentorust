
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    /// 等待pcap启动
    WaitingLoop,
    /// 开始认证
    StartAuth {
        dest_mac: [u8; 6]
    },
    /// 请求用户名
    EapRequestIdentity {
        dest_mac: [u8; 6],
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        id : u8,
    },
    /// 验证密码
    EapRequestPassword {
        dest_mac: [u8; 6],
        ipv4: [u8; 4],
        ipv6: [u8; 16],
        id : u8,
        seed: [u8; 128],
        seed_len: u8,
    },
    /// 认证成功
    AuthSuccess {
        dest_mac: [u8; 6],
    },
    /// 重新连接
    Reconnect,
    /// 下线
    Logoff,
    /// 心跳
    Heartbeat {
        dest_mac: [u8; 6],
    }
}