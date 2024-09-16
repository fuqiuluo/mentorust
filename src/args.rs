use clap_derive::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mentorust")]
#[command(about = "针对EAP协议锐捷校园网认证 - 三伏天秋不洛", version = "1.0.0", author = "fuqiuluo")]
pub struct EapArgs {
    #[command(subcommand)]
    pub command: EapCommands,
}

#[derive(Subcommand)]
pub enum EapCommands {
    /// 校园网认证
    Auth {
        /// 网卡名称
        #[arg(short, long, default_value = "")]
        nic: String,

        /// dhcp模式 1(二次认证) 2(认证后) 3(认证前)
        #[arg(short, long, default_value_t = 0)]
        dhcp_mode: u8,

        /// 用户名
        #[arg(short, long)]
        username: String,

        /// 密码
        #[arg(short, long)]
        password: String,

        /// 是否后台运行
        #[arg(short, long, default_value_t = false)]
        background: bool,
    },
    /// 解码配置文件
    DecodeConfig {
        /// 网卡名称
        #[arg(short, long)]
        path: String,
    },
    /// 自动抓包分析
    AutoCapture {
        /// 网卡名称(开启抓包器后请重走一遍认证流程)
        #[arg(short, long, default_value = "")]
        nic: String,
    },
    /// 打印所有Mac地址等信息
    PrintMac
}
