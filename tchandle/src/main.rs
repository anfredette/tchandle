use anyhow::anyhow;
use anyhow::Result;
use aya::programs::tc::{SchedClassifierLink, TcOptions};
use aya::programs::{tc, Link, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json;
use std::mem;
use std::{fs, io::BufReader};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    /// Interface to install filters on
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    /// Whether to "install" or "delete"
    #[clap(short, long, default_value = "load")]
    action: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum Direction {
    Ingress,
    Egress,
}

#[derive(Debug, Serialize, Deserialize)]
struct TcProgram {
    if_name: String,
    direction: Direction,
    priority: u16,
    handle: u32,
}

const PATH: &str = "./saved_tc_link";

impl TcProgram {
    fn save(&self) -> Result<(), anyhow::Error> {
        serde_json::to_writer(&fs::File::create(PATH).unwrap(), &self)?;
        Ok(())
    }

    fn load() -> Result<Self, anyhow::Error> {
        let file = fs::File::open(PATH)?;
        let reader = BufReader::new(file);
        let prog = serde_json::from_reader(reader)?;
        Ok(prog)
    }

    fn delete() -> Result<(), anyhow::Error> {
        fs::remove_file(PATH)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tchandle"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tchandle"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);

    match opt.action.as_str() {
        "load" => {
            info!("loading program tctest1");
            let program1: &mut SchedClassifier = bpf.program_mut("tctest1").unwrap().try_into()?;
            program1.load()?;

            info!("attaching program tctest1");
            let link_id_1 = program1.attach_with_options(
                &opt.iface,
                TcAttachType::Ingress,
                TcOptions {
                    priority: 50,
                    handle: 3,
                },
            )?;

            info!("calling take link for program 1 (tctest1)");
            let link_1 = program1.take_link(link_id_1)?;

            let prog1_info = TcProgram {
                if_name: opt.iface.clone(),
                direction: Direction::Ingress,
                priority: link_1.priority(),
                handle: link_1.handle(),
            };

            info!("saving program info");
            prog1_info.save()?;

            mem::forget(link_1);
        }

        "delete" => {
            let prog1_info = TcProgram::load().unwrap_or_else(|error| {
                panic!("Problem opening the file: {:?}", error);
            });

            let attach_type = match prog1_info.direction {
                Direction::Ingress => TcAttachType::Ingress,
                Direction::Egress => TcAttachType::Egress,
            };

            let new_link_1 = SchedClassifierLink::attached(
                &prog1_info.if_name,
                attach_type,
                prog1_info.priority,
                prog1_info.handle,
            )?;

            info!("calling new_link_1.detach (tctest1)");
            let detach_result = new_link_1.detach();

            match detach_result {
                Ok(()) => info!("new_link_1.detach() succeeded"),
                Err(e) => info!("new_link_1.detach() failed. Error: {:#?}", e),
            }

            info!("calling TcProgram::delete()");
            let _ = TcProgram::delete();
        }

        _ => {
            return Err(anyhow!(
                "Invalid action: {}.  Valid actions are \"load\" and \"delete\"",
                opt.action
            ));
        }
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
