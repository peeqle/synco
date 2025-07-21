use local_ip_address::list_afinet_netifas;
use std::net::{IpAddr, Ipv4Addr};
use log::info;

pub fn get_local_ip() -> Option<IpAddr> {
    let ifas = list_afinet_netifas().unwrap();

    if let Some((_, ipaddr)) = ifas
        .iter()
        .find(|(name, ipaddr)| (*name).contains("wlp") && matches!(ipaddr, IpAddr::V4(_)))
    {
        info!("Using current device WLP address: {:?}", ipaddr);
        return Some(*ipaddr);
    }

    Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
}
