mod net;
mod pcapx;
mod packets;
mod eap;
mod args;
mod config;
mod err;

#[cfg(target_os = "windows")]
use windows::core::PCSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{BOOL};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOA, CREATE_NO_WINDOW, CreateProcessA};
#[cfg(target_os = "windows")]
use windows::core::PSTR;
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

#[cfg(target_os = "linux")]
use daemonize::Daemonize;

use std::cell::UnsafeCell;
use std::ffi::CString;
use std::fmt::format;
use std::net::IpAddr;
use std::process::exit;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::mpsc::{RecvError, RecvTimeoutError};
use std::{ptr, thread};
use std::fs::File;
use std::time::Duration;
use clap::Parser;
use encoding_rs::GBK;
use log::{debug, error, info, warn};
use pcap::{Active, Capture, Device, State};
use pnet::datalink::NetworkInterface;
use crate::args::{EapArgs, EapCommands};
use crate::eap::{Status, CODE_FAILURE, CODE_REQUEST, CODE_SUCCESS, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE};
use crate::err::EapError;
use crate::pcapx::SharedCapture;

fn main() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let args = EapArgs::parse();

    match args.command {
        EapCommands::Auth { nic, username, password, dhcp_mode, background, anti_share } => {
            if cfg!(target_os = "linux") {
                if unsafe { libc::geteuid() } != 0 {
                    error!("请使用root权限运行！");
                    exit(-4);
                }
            }

            if background {
                #[cfg(target_os = "windows")]
                no_windows_run(nic, username, password, dhcp_mode);
                #[cfg(target_os = "linux")]
                no_console_run(nic, username, password, dhcp_mode);
            } else {
                //thread::sleep(Duration::from_secs(5));
                auth(nic, username, password, dhcp_mode);
            }
        },
        EapCommands::DecodeConfig { path } => {
            info!("解码配置文件: {}", path);
            eap::utils::decode_config(&path);
        }
        EapCommands::AutoCapture { .. } => {
            unimplemented!()
        }
        EapCommands::PrintMac => {
            net::print_all_network_mac();
        }
    }
}

#[cfg(target_os = "linux")]
fn no_console_run(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
) {
    let out_file = std::env::var("MENTORUST_OUT_FILE")
        .unwrap_or("/tmp/mentorust.out".to_string());
    let pid_file = std::env::var("MENTORUST_OUT_FILE")
        .unwrap_or("/tmp/mentorust.pid".to_string());

    let stdout = File::create(out_file).unwrap();
    let stderr = stdout.try_clone().unwrap();

    // working_directory fetch
    let current_direction = std::env::current_dir().unwrap();

    let daemonize = Daemonize::new()
        .pid_file(pid_file)
        .chown_pid_file(true)
        .working_directory(current_direction)
        .umask(0o777)
        .stdout(stdout)
        .stderr(stderr)
        .privileged_action(|| "Executed before drop privileges");

    match daemonize.start() {
        Ok(_) => {
            info!("程序将作为系统守护进程切换到后台运行");
            auth(nic_name, username, password, dhcp_mode);
        },
        Err(e) => error!("后台运行失败, {}", e),
    }
}

#[cfg(target_os = "windows")]
fn no_windows_run(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
) {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");
    let command_line = CString::new(format!("{} auth -n \"{}\" -d {} -u {} -p {}", current_exe.display(), nic_name, dhcp_mode, username, password))
        .expect("Failed to convert command line to CString");

    //info!("Cmd: {:?}", command_line.to_string_lossy());

    unsafe {
        let mut startup_info = STARTUPINFOA::default();
        let mut process_info = PROCESS_INFORMATION::default();
        startup_info.cb = size_of::<STARTUPINFOA>() as u32;

        let success = CreateProcessA(
            PCSTR::null(),
            PSTR(command_line.as_ptr() as *mut _),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None, // todo(后台进程环境变量丢失?)
            PCSTR::null(),
            &mut startup_info,
            &mut process_info,
        );

        if success.is_ok() {
            debug!("CreateProcessA success");
            let pid = process_info.dwProcessId;
            info!("进程已切换到后台运行，PID: {}", pid);
            exit(pid as i32);
        } else {
            error!("创建后台进程失败 无法后台运行: {}", windows::core::Error::from_win32());
        }
    }
}

fn auth(
    nic_name: String,
    username: String,
    password: String,
    dhcp_mode: u8
) {
    let Some(nic) = find_nic(&nic_name) else {
        return;
    };
    info!("找到认证服务器或WAN网卡: {:?}", nic.desc.as_ref().unwrap_or(&nic.name));
    let Some(inet) = net::get_network_interface_by_name(&nic.name) else {
        error!("未找到网卡({})的MAC地址，请检查网卡名称是否正确！", nic.name);
        return;
    };

    let mut ipv4 = [0u8; 4];
    let mut ipv6 = [0u8; 16];

    for ip in inet.ips {
        match ip.ip() {
            IpAddr::V4(v4) => {
                ipv4 = v4.octets()
            }
            IpAddr::V6(v6) => {
                ipv6 = v6.to_bits().to_be_bytes()
            }
        }
    }
    let mac = inet.mac.unwrap().to_string().to_lowercase();
    if mac.len() != 17 {
        error!("MAC地址({})格式错误，请检查MAC地址是否正确！", mac);
        return;
    }
    info!("网卡({})IPv4地址: {:?}", nic.desc.as_ref().unwrap_or(&nic.name), ipv4);
    info!("网卡({})IPv6地址: {:?}", nic.desc.as_ref().unwrap_or(&nic.name), ipv6);
    info!("网卡({})MAC地址: {:?}", nic.desc.as_ref().unwrap_or(&nic.name), mac);
    let cap = match open_pcap(nic.clone(), &mac) {
        Err(e) => {
            error!("监听网卡数据包失败: {:?}", e);
            return;
        }
        Ok(cap) => {
            cap
        }
    };
    let cap = SharedCapture::new(cap);

    let mut local_mac = [0u8; 6];
    let mut dest_mac = if dhcp_mode == 1 {
        [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03]
    } else {
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]
    };
    hex::decode_to_slice(mac.replace(":", ""), &mut local_mac).unwrap();

    let receiver = start_loop(cap.clone(), ipv4, ipv6); // 开始监听
    let packet_sender = spawn_packet_sender(cap.clone(), local_mac, username, password); // 发送数据包

    if dhcp_mode == 3 {
        panic!("不支持认证前dhcp")
    } else {
        packet_sender.send(Status::StartAuth {
            dest_mac
        }).expect("发送寻找认证服务器包失败"); // 开始认证
    }

    let max_retries = std::env::var("MENTORUST_MAX_RETRIES")
        .unwrap_or("3".to_string()).parse::<i32>().unwrap_or(3);
    let mut retries = 0;
    loop {
        match receiver.recv_timeout(Duration::from_secs(15)) {
            Ok(status) => {
                if let Status::Reconnect = status {
                    warn!("10s后重新认证...");
                    thread::sleep(Duration::from_secs(10));
                    packet_sender.send(Status::StartAuth {
                        dest_mac: [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03]
                    }).expect("发送尝试重新认证包失败");
                    continue
                }
                if let Status::AuthSuccess { dest_mac: new_dest_mac } = status {
                    retries = 0;
                    dest_mac = new_dest_mac;
                }
                packet_sender.send(status).expect("更新认证器状态失败");
            }
            Err(RecvTimeoutError::Timeout) => {
                retries += 1;
                match cap.status() {
                    Status::AuthSuccess { dest_mac: _dest_mac } => {
                        if retries == 2 {
                            retries = 0;
                            //info!("发送心跳包...");
                            packet_sender.send(Status::Heartbeat { dest_mac })
                                .expect("发送心跳包失败");
                        }
                    }
                    _ => {
                        if max_retries >= 0 && retries > max_retries {
                            error!("认证失败，重试次数已达上限({})！", max_retries);
                            exit(4);
                        }
                        warn!("第{}次认证服务器无响应，10s后重新认证，直到达到最大{}次限制...", retries, max_retries);
                        thread::sleep(Duration::from_secs(10));
                        packet_sender.send(Status::StartAuth {
                            dest_mac: [0x01, 0xd0, 0xf9, 0x00, 0x00, 0x03]
                        }).expect("发送尝试重新认证包失败");
                    }
                }
            },
            Err(RecvTimeoutError::Disconnected) => {
                error!("认证器状态接收器已断开，请检查认证器状态接收器是否正常！");
                exit(-2);
            }
        };
    }
}

fn spawn_packet_sender(
    sc: Arc<SharedCapture>,
    local_mac: [u8; 6],
    username: String,
    password: String,
) -> std::sync::mpsc::Sender<Status> {
    let (sender, mut receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        loop {
            let status = match receiver.recv() {
                Ok(status) => status,
                Err(_) => {
                    break
                }
            };
            match status {
                Status::Reconnect | Status::Heartbeat { .. } => {
                    // nothing
                }
                _ => {
                    sc.set_status(status);
                }
            }
            match status {
                Status::WaitingLoop => panic!("Error: WaitingLoop"), // waiting_loop should not be sent
                Status::StartAuth { dest_mac } => {
                    info!("寻找认证服务器...");
                    let packet = packets::build_hello_packet(
                        &dest_mac,
                        &local_mac,
                    );
                    sc.cap_mut().sendpacket(packet.as_slice()).unwrap();
                }
                Status::EapRequestIdentity { dest_mac, ipv4, ipv6, id } => {
                    info!("发送用户名到认证服务器(mac = {}, id = {})...", dest_mac.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":"), id);
                    let packet = packets::build_identity_packet(&dest_mac, &local_mac, &ipv4, &ipv6, username.as_str(), id);
                    sc.cap_mut().sendpacket(packet.as_slice()).unwrap();
                }
                Status::EapRequestPassword { dest_mac, ipv4, ipv6, id, seed, seed_len } => {
                    info!("发送密码到认证服务器(mac = {}, id = {}, seed_len = {})...", dest_mac.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":"), id, seed_len);
                    let packet = packets::build_password_packet(&dest_mac, &local_mac, &ipv4, &ipv6, username.as_str(), password.as_str(), id, &seed[0..seed_len as usize]);
                    sc.cap_mut().sendpacket(packet.as_slice()).unwrap();
                }
                Status::AuthSuccess { .. } => {
                    info!("认证成功...欢迎来到互联网世界！");
                }
                Status::Reconnect => unreachable!(),
                Status::Logoff => {
                    exit(0);
                }
                Status::Heartbeat { dest_mac } => {
                    let packet = packets::build_heartbeat_packet(&dest_mac, &local_mac);
                    sc.cap_mut().sendpacket(packet.as_slice()).unwrap();
                }
            }
        }
    });
    sender
}

fn start_loop(sc: Arc<SharedCapture>, ipv4: [u8; 4], ipv6: [u8; 16]) -> std::sync::mpsc::Receiver<Status> {
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        loop {
            if sc.status() == Status::Logoff {
                break
            }
            let cap = sc.cap_mut();
            let _ = cap.for_each(None, |packet| {
                if packet.data[12] != 0x88 || packet.data[13] != 0x8e {
                    if option_env!("MENTORUST_DEBUG") == Some("1") {
                        warn!("Pcap loop: not 0x888e: {}", packet.data[12..14].iter().map(|x| format!("{:02x}", x)).collect::<String>());
                    }
                    return;
                }
                if packet.data[18] == CODE_REQUEST && packet.data[22] == EAP_TYPE_IDENTITY {
                    sender.send(Status::EapRequestIdentity {
                        dest_mac: [packet.data[6], packet.data[7], packet.data[8], packet.data[9], packet.data[10], packet.data[11]],
                        ipv4,
                        ipv6,
                        id: packet.data[19],
                    }).unwrap();
                } else if packet.data[18] == CODE_REQUEST && packet.data[22] == EAP_TYPE_MD5_CHALLENGE {
                    let seed_len = packet.data[23] as usize;
                    let mut seed = [0u8; 128];
                    (&mut seed[0..seed_len]).copy_from_slice(&packet.data[24 .. (seed_len + 24)]);
                    sender.send(Status::EapRequestPassword {
                        dest_mac: [packet.data[6], packet.data[7], packet.data[8], packet.data[9], packet.data[10], packet.data[11]],
                        ipv4,
                        ipv6,
                        id: packet.data[19],
                        seed_len: seed_len as u8,
                        seed
                    }).unwrap();
                } else if packet.data[18] == CODE_SUCCESS {
                    let offset = 0x1c + packet.data[0x1b] as usize + 0x69 + 39;
                    if offset < packet.data.len() {
                        let len = if packet.data[offset - 1] as usize - 2 > packet.data.len() - offset {
                            packet.data.len() - offset
                        } else {
                            packet.data[offset - 1] as usize - 2
                        };
                        let data = &packet.data[offset..offset + len];
                        let msg = GBK.decode(data).0;
                        if msg.starts_with("\n") || msg.starts_with("\r") {
                            info!("系统公告：{}", msg)
                        } else {
                            info!("系统公告：\n{}", msg)
                        }
                    }
                    sender.send(Status::AuthSuccess {
                        dest_mac: [packet.data[6], packet.data[7], packet.data[8], packet.data[9], packet.data[10], packet.data[11]],
                    }).unwrap();
                } else if packet.data[18] == CODE_FAILURE {
                    if packet.data.len() > 0x1b && packet.data[0x1b] != 0 { // 存在错误提示
                        let len = packet.data[0x1b] as usize;
                        let data = &packet.data[0x1c..0x1c + len];
                        let msg = GBK.decode(data).0;
                        error!("系统提示：{}", msg)
                    }
                    match sc.status() {
                        Status::Heartbeat { .. } => {}
                        Status::WaitingLoop => {
                            error!("报错预测：认证失败，请检查用户名和密码是否正确！");
                            exit(1);
                        }
                        Status::Reconnect | Status::StartAuth { .. } => {
                            error!("报错预测：寻找认证服务器失败...");
                            exit(-1);
                        }
                        Status::EapRequestIdentity { .. } => {
                            error!("报错预测：\n1，锐捷私有扩展数据校验不通过！\n2，用户名错误，请检查用户名是否正确！");
                            exit(2);
                        }
                        Status::EapRequestPassword { .. } => {
                            error!("报错预测：\n1，账号密码错误，请检查密码是否正确！\n2，MAC地址绑定错误，请解绑已绑定的MAC地址！");
                            exit(3);
                        }
                        Status::AuthSuccess { .. } => {
                            // 掉线 需要重连
                            warn!("报错预测：网络掉线或被踢下线...正在尝试重新连接...");
                            sender.send(Status::Reconnect).unwrap();
                            return;
                        }
                        Status::Logoff => {
                            exit(0)
                        }
                    }
                } else {
                    if option_env!("MENTORUST_DEBUG") == Some("1") {
                        warn!("Pcap loop: Unknown packet: {:?}", hex::encode(packet.data));
                        exit(1)
                    }
                }
            });
        }

    });
    receiver
}

fn open_pcap(
    nic: Device,
    mac: &str
) -> Result<Capture<Active>, EapError> {
    let mut cap = Capture::from_device(nic)?
        .immediate_mode(true)
        .snaplen(2048)
        .promisc(false)
        .timeout(1000)
        .buffer_size(256)
        .open()?;
    let rule = format!("ether proto 0x888e and (ether dst {} or ether dst 01:80:c2:00:00:03) and not ether src {}", mac, mac);
    cap.filter(&rule, false).map_err(|e|
        panic!("Error setting filter: {:?}", e)
    ).unwrap();
    Ok(cap)
}

fn find_nic(nic: &str) -> Option<Device> {
    let devices = Device::list()
        .map_err(|e| panic!("Error listing devices: {:?}", e))
        .unwrap();

    if nic.is_empty() {
        info!("未指定网卡，寻找认证服务器以及WAN网卡中...");
        let dev = devices.iter().filter(|dev| {
            !dev.addresses.is_empty() && dev.addresses.iter().any(|addr| addr.addr.is_ipv4() && addr.addr.to_string().starts_with("10."))
        }).collect::<Vec<_>>();

        if dev.is_empty() {
            error!("未找到认证服务器或WAN网卡，没有找到`10.x.x.x`IP的网卡，请手动指定网卡！");
            let names = devices
                .iter()
                .map(|dev| dev.name.clone())
                .collect::<Vec<_>>()
                .join("\n");
            error!("当前网卡列表: \n{}", names);
            return None;
        }

        if dev.len() == 1 {
            Some(dev[0].clone())
        } else {
            if cfg!(target_os = "linux") {
                info!("存在多个`10.x.x.x`IP的网卡，优先匹配`en`开头的网卡！");
                let Some(en) = dev.iter().find(|dev| dev.name.starts_with("en") || dev.name.starts_with("eth")).cloned() else {
                    error!("未找到认证服务器或WAN网卡，没有符合预设的网卡，请手动指定网卡！");
                    let names = devices
                        .iter().map(|dev| dev.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    error!("当前网卡列表: {}", names);
                    return None;
                };
                return Some(en.clone());
            }
            error!("未找到认证服务器或WAN网卡，没有符合预设的网卡，请手动指定网卡！");
            let names = devices
                .iter().map(|dev| dev.name.clone())
                .collect::<Vec<_>>()
                .join("\n");
            error!("当前网卡列表: {}", names);
            None
        }
    } else {
        let Some(nic) = devices.iter().find(|dev| dev.name == nic) else {
            error!("未找到指定的网卡({})，请检查网卡名称是否正确！", nic);
            let names = devices
                .iter().map(|dev| dev.name.clone())
                .collect::<Vec<_>>()
                .join("\n");
            error!("当前网卡列表: {}", names);
            return None;
        };
        Some(nic.clone())
    }
}
