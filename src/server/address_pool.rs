use dashmap::DashSet;
use ipnet::{IpAddrRange, IpNet, Ipv4AddrRange, Ipv6AddrRange};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Represents a pool of addresses from which addresses can be requested and released.
pub struct AddressPool {
    network: IpNet,
    used_addresses: DashSet<IpAddr>,
}

impl AddressPool {
    /// Creates a new instance of an `AddressPool`.
    ///
    /// ### Arguments
    /// - `network` - the network address and mask
    pub fn new(network: IpNet) -> Self {
        let pool = Self {
            network,
            used_addresses: DashSet::new(),
        };

        pool.reset();

        pool
    }

    /// Returns the next available address if such an address exists.
    pub fn next_available_address(&self) -> Option<IpNet> {
        let mut range = match self.network {
            IpNet::V4(network) => {
                IpAddrRange::V4(Ipv4AddrRange::new(network.network(), network.broadcast()))
            }
            IpNet::V6(network) => {
                IpAddrRange::V6(Ipv6AddrRange::new(network.network(), network.broadcast()))
            }
        };

        range
            .find(|address| !self.used_addresses.contains(address))
            .map(|address| {
                self.used_addresses.insert(address);
                IpNet::with_netmask(address, self.network.netmask())
                    .expect("Netmask will always be valid")
            })
    }

    /// Releases the specified address so it can be used in further requests.
    ///
    /// ### Arguments
    /// - `address` - the address to release
    pub fn release_address(&self, address: &IpAddr) {
        self.used_addresses.remove(address);
    }

    /// Reserves the specified IP if it is available and valid
    pub fn reserve_if_available(&self, net: IpNet) -> Option<IpNet> {
        let ip = net.addr();

        // check if ip belongs to pool
        if !self.network.contains(&ip) {
            return None;
        }

        // check if already used
        if self.used_addresses.contains(&ip) {
            return None;
        }

        // reserve
        self.used_addresses.insert(ip);

        // 必要なら元のprefixで返す
        Some(net)
    }

    /// change
    /// Resets the address pool by releasing all addresses.
    pub fn reset(&self) {
        self.used_addresses.clear();
        self.used_addresses.insert(self.network.network());
        self.used_addresses.insert(self.network.addr());
        self.used_addresses.insert(self.network.broadcast());

        // change
        match self.network {
            IpNet::V4(net) => {
                let base = net.network();
                let octets = base.octets();

                for offset in 2..=5 {
                    let ip = u32::from_be_bytes(octets).checked_add(offset).unwrap();
                    let addr = Ipv4Addr::from(ip);
                    self.used_addresses.insert(IpAddr::V4(addr));
                }
            }
            IpNet::V6(net) => {
                let base = net.network();
                let segments = base.segments(); // u16 の配列
                for i in 1..=4 {
                    let mut new_segments = segments;
                    new_segments[7] = new_segments[7].checked_add(i).unwrap();
                    let addr = Ipv6Addr::from(new_segments);
                    self.used_addresses.insert(IpAddr::V6(addr));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::server::address_pool::AddressPool;
    use ipnet::{IpNet, Ipv4Net};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_address_pool() {
        let pool = AddressPool::new(IpNet::V4(
            Ipv4Net::with_netmask(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(255, 255, 255, 240),
            )
            .unwrap(),
        ));

        assert_eq!(
            pool.next_available_address().unwrap(),
            IpNet::V4(
                Ipv4Net::with_netmask(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(255, 255, 255, 252),
                )
                .unwrap()
            )
        );

        assert_eq!(pool.next_available_address(), None);
        pool.release_address(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

        assert_eq!(
            pool.next_available_address().unwrap(),
            IpNet::V4(
                Ipv4Net::with_netmask(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(255, 255, 255, 252),
                )
                .unwrap()
            )
        );
    }
}
