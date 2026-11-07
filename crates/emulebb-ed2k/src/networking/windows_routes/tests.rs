use super::{default_route_indices, indices_from_rows};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2},
    Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_INET},
};

fn route(index: u32, prefix_length: u8) -> MIB_IPFORWARD_ROW2 {
    MIB_IPFORWARD_ROW2 {
        InterfaceIndex: index,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    ..Default::default()
                },
            },
            PrefixLength: prefix_length,
        },
        ValidLifetime: u32::MAX,
        ..Default::default()
    }
}

#[test]
fn on_link_tunnel_default_is_owned_by_its_index_without_a_gateway_or_name() {
    // The zeroed NextHop models a tunnel's on-link default route. Adapter
    // gateways, friendly names, and GUID strings are not needed for ownership.
    assert_eq!(indices_from_rows(&[route(37, 0)]), [37].into());
}

#[test]
fn distinct_defaults_remain_ambiguous_and_duplicates_collapse() {
    assert_eq!(
        indices_from_rows(&[route(37, 0), route(8, 0), route(37, 0)]),
        [37, 8].into()
    );
}

#[test]
fn specific_expired_loopback_and_non_ipv4_routes_are_not_defaults() {
    let mut expired = route(1, 0);
    expired.ValidLifetime = 0;
    let mut loopback = route(2, 0);
    loopback.Loopback = true;
    let mut ipv6 = route(3, 0);
    ipv6.DestinationPrefix.Prefix = SOCKADDR_INET {
        si_family: AF_INET6,
    };
    assert!(indices_from_rows(&[route(4, 24), expired, loopback, ipv6, route(0, 0)]).is_empty());
    assert!(indices_from_rows(&[]).is_empty());
}

#[test]
fn native_route_snapshot_is_readable_without_requiring_a_default_route() {
    default_route_indices().expect("read native IPv4 route snapshot, including on offline hosts");
}
