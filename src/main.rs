//! Dynamic (subprocess) entrypoint for the caddy plugin.
//!
//! A DUAL-facet plugin: one `Plugin` builder chain registers BOTH the
//! [`ServiceBackend`](caddy::CaddyBackend) (generic `service.*` lifecycle) AND
//! the read-only `caddy.` `#[orca_tool]` surface (endpoint registry CRUD +
//! admin-API status/route inspection). The builder emits all the wire dispatch,
//! so the plugin hand-writes no op strings and owns no runtime — it reaches orca
//! only through the socket.
plugin_toolkit::instrument::bootstrap!();

use caddy::CaddyBackend;
use plugin_toolkit::plugin::Plugin;

// Force-link this plugin's OWN lib crate so the linker doesn't dead-strip the
// rlib (and with it every `#[orca_tool]` / `#[endpoint_resource]` registration).
#[allow(unused_imports)]
use caddy::tools as _;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("caddy")
        .version(env!("CARGO_PKG_VERSION"))
        .service(CaddyBackend::new("caddy"))
        .tools(["caddy."])
        .serve()
}
