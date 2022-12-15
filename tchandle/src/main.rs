use aya::programs::tc::{SchedClassifierLink, TcOptions};
use aya::programs::{tc, Link, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use core::time;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{mem, thread};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
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

    let delay = time::Duration::new(5, 0);

    let program0: &mut SchedClassifier = bpf.program_mut("tctest0").unwrap().try_into()?;
    program0.load()?;
    let link_id_0 = program0.attach(&opt.iface, TcAttachType::Ingress)?;
    info!("\nlink_id_0: {:#?}", link_id_0);

    info!("Sleep...");
    thread::sleep(delay);

    let program1: &mut SchedClassifier = bpf.program_mut("tctest1").unwrap().try_into()?;
    program1.load()?;
    let link_id_1 = program1.attach_with_options(
        &opt.iface,
        TcAttachType::Ingress,
        TcOptions {
            priority: 50,
            handle: 3,
        },
    )?;
    info!("\nlink_id_1: {:#?}", link_id_1);

    info!("Sleep...");
    thread::sleep(delay);

    info!("calling take link for program 1 (tctest1)");
    let link_1 = program1.take_link(link_id_1)?;
    info!("\nlink_1: {:#?}", link_1);

    info!(
        "priority: {}, handle: {}",
        link_1.priority(),
        link_1.handle()
    );

    let prog1_info = TcProgram {
        if_name: opt.iface.clone(),
        direction: Direction::Ingress,
        priority: link_1.priority(),
        handle: link_1.handle(),
    };

    let attach_type = match prog1_info.direction {
        Direction::Ingress => TcAttachType::Ingress,
        Direction::Egress => TcAttachType::Egress,
    };

    let link_1_copy = SchedClassifierLink::new_tc_link(
        &prog1_info.if_name,
        attach_type,
        prog1_info.priority,
        prog1_info.handle,
    )?;

    info!("\nlink_1_copy\n{:#?}", link_1_copy);

    info!("Sleep...");
    thread::sleep(delay);

    info!("Adding program 2 (tctest2)");
    let program2: &mut SchedClassifier = bpf.program_mut("tctest2").unwrap().try_into()?;
    program2.load()?;
    let link_id_2 = program2.attach_with_options(
        &opt.iface,
        TcAttachType::Ingress,
        TcOptions {
            priority: 50,
            ..Default::default()
        },
    )?;
    info!("\nlink_id_2: {:#?}", link_id_2);

    info!("Sleep...");
    thread::sleep(delay);

    info!("calling take link for program 2 (tctest2)");
    let link_2 = program2.take_link(link_id_2)?;
    info!("\nlink_2: {:#?}\n", link_2);

    info!(
        "priority: {}, handle: {}",
        link_2.priority(),
        link_2.handle()
    );

    let _prog2_info = TcProgram {
        if_name: opt.iface.clone(),
        direction: Direction::Ingress,
        priority: link_2.priority(),
        handle: link_2.handle(),
    };

    mem::forget(link_2);

    info!("Sleep...");
    thread::sleep(delay);

    info!("calling link_1_copy.detach (tctest1)");
    link_1_copy.detach()?;

    info!("Sleep...");
    thread::sleep(delay);

    info!("calling link_1.detach (tctest1)");
    let result = link_1.detach();

    match result {
        Err(e) => info!("Error, as expected, calling link_1.detach: ({:#?})", e),
        Ok(_) => info!("No error when calling link1.detach"),
    };

    let invalid_link = SchedClassifierLink::new_tc_link(&prog1_info.if_name, attach_type, 500, 4)?;

    info!("calling invalid_link.detach (tctest1)");
    let result = invalid_link.detach();

    match result {
        Err(e) => info!(
            "Error, as expected, calling invalid_link.detach: ({:#?})",
            e
        ),
        Ok(_) => info!("No error when calling link1.detach"),
    };

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
