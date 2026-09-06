//! Dynamic (subprocess) entrypoint for the caddy plugin.
//!
//! A single-facet `service` plugin: the [`Plugin`](plugin_toolkit::plugin::Plugin)
//! builder registers the [`ServiceBackend`] and emits all the wire dispatch, so
//! the plugin hand-writes no op strings and owns no runtime — it reaches orca
//! only through the socket.
plugin_toolkit::instrument::bootstrap!();

use caddy::CaddyBackend;
use plugin_toolkit::plugin::Plugin;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("caddy")
        .version(env!("CARGO_PKG_VERSION"))
        .service(CaddyBackend::new("caddy"))
        .serve()
}
