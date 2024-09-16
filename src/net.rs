use datalink::NetworkInterface;
use pnet::datalink;

pub(crate) fn print_all_network_mac() {
    let interfaces = datalink::interfaces();

    for interface in interfaces {
        if let Some(mac) = interface.mac {
            println!("Interface: {} MAC Address: {}", interface.name, mac);
        } else {
            println!("Interface: {} has no MAC address.", interface.name);
        }
        println!("  IP addresses: {:?}", interface.ips);

    }
}

pub(crate) fn get_network_interface_by_name(name: &str) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces.iter().find(|dev| dev.name == name).cloned()
}


#[test]
fn test_get_dns() {
    print_all_network_mac()
}