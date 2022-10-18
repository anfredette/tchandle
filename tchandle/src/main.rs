//use aya::programs::tc::qdisc_detach_program;
use aya::programs::{tc, SchedClassifier, TcAttachType, TcError};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
//use core::time;
use log::{info, warn};
//use std::thread;
use std::io::ErrorKind::AlreadyExists;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
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

    //let delay = time::Duration::new(5, 0);

    let handle: u32 = 4;

    let program0: &mut SchedClassifier = bpf.program_mut("tchandle").unwrap().try_into()?;
    program0.load()?;
    let link_id_0 = program0.attach(&opt.iface, TcAttachType::Ingress, 50, handle);
    info!("\nlink_id_0: {:#?}", link_id_0);

    let program1: &mut SchedClassifier = bpf.program_mut("tctest1").unwrap().try_into()?;
    program1.load()?;
    let attach_result = program1.attach(&opt.iface, TcAttachType::Ingress, 50, handle);

    match attach_result {
        Ok(link_id_1) => {
            info!("\nlink_id_1: {:#?}", link_id_1);
        }
        Err(error) => {
            info!("\nerror: {:#?}", error);
            match error {
                aya::programs::ProgramError::TcError(tc_error) => match tc_error {
                    TcError::NetlinkError { io_error } => {
                        if io_error.kind() == AlreadyExists {
                            info!("There is already a program attached with handle {}", handle);
                            info!("error: \n{:#?}", TcError::NetlinkError { io_error });
                        };
                    }
                    TcError::AlreadyAttached => panic!("error: {}", TcError::AlreadyAttached),
                },
                _ => panic!("Unexpected error: {:#?}", error),
            };
        }
    }

    /*
    let program1: &mut SchedClassifier = bpf.program_mut("tctest1").unwrap().try_into()?;
    program1.load()?;
    let link_id_1 = program1.attach(&opt.iface, TcAttachType::Ingress, 50, 1)?;
    info!("\nlink_id_1: {:#?}", link_id_1);

    info!("Sleep...");
    thread::sleep(delay);

    let program2: &mut SchedClassifier = bpf.program_mut("tctest2").unwrap().try_into()?;
    program2.load()?;
    let link_id_2 = program2.attach(&opt.iface, TcAttachType::Ingress, 50, 3)?;
    info!("\nlink_id_2: {:#?}", link_id_2);

    info!("Sleep...");
    thread::sleep(delay);

    info!("Detaching tctest2");
    program2.detach(link_id_2)?;

    info!("Sleep...");
    thread::sleep(delay);

    info!("Calling qdisc_detach_program");
    qdisc_detach_program(&opt.iface, TcAttachType::Ingress, "tctest1")?;

    info!("Sleep...");
    thread::sleep(delay);
    */

    //info!("calling take link for program 0 (tchandle)");
    //program0.take_link(link_id_0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
