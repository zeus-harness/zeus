mod collaboration;
mod control_plane;
mod execution;
mod identity;
mod operations;

use super::PublicRoute;

#[derive(Clone, Copy)]
pub(crate) struct PublicRoutes;

pub(crate) const PUBLIC_ROUTES: PublicRoutes = PublicRoutes;

pub(crate) fn iter() -> PublicRouteIter {
    PublicRouteIter {
        groups: [
            operations::ROUTES,
            identity::ROUTES,
            control_plane::ROUTES,
            collaboration::ROUTES,
            execution::ROUTES,
        ],
        group_index: 0,
        route_index: 0,
    }
}

pub(crate) struct PublicRouteIter {
    groups: [&'static [PublicRoute]; 5],
    group_index: usize,
    route_index: usize,
}

impl Iterator for PublicRouteIter {
    type Item = &'static PublicRoute;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let group = self.groups.get(self.group_index)?;
            if let Some(route) = group.get(self.route_index) {
                self.route_index += 1;
                return Some(route);
            }
            self.group_index += 1;
            self.route_index = 0;
        }
    }
}

impl IntoIterator for PublicRoutes {
    type Item = &'static PublicRoute;
    type IntoIter = PublicRouteIter;

    fn into_iter(self) -> Self::IntoIter {
        iter()
    }
}
