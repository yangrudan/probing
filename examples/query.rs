use std::sync::Arc;

use anyhow::Result;

use engine::core::pretty;
use engine::core::Engine;
use engine::plugins::files::FilesPlugin;

use engine::plugins::envs::EnvPlugin;
use engine::plugins::kmsg::KMsgPlugin;

#[tokio::main]
async fn main() -> Result<()> {
    let engine = Engine::new();

    engine.enable("probe".to_string(), Arc::new(FilesPlugin::default()))?;
    engine.enable("probe".to_string(), Arc::new(EnvPlugin::new("envs".to_string(), "process".to_string())))?;
    engine.enable("probe".to_string(), Arc::new(KMsgPlugin::new("kmsg".to_string(), "system".to_string())))?;


    let query = std::env::args().collect::<Vec<_>>()[1].clone();
    let rb = engine.sql(query.as_str()).await?.collect().await?;

    pretty::print_batches(&rb)?;

    Ok(())
}
