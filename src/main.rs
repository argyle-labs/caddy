plugin_toolkit::instrument::bootstrap!();

#[allow(unused_imports)]
use caddy::tools as _;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    plugin_toolkit::plugin::Plugin::named("caddy")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["caddy."])
        .service(caddy::CaddyBackend::new("caddy"))
        .serve()
}
